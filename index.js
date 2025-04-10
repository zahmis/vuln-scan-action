const core = require('@actions/core');
const github = require('@actions/github');
const axios = require('axios');

// Perplexity APIのエンドポイント
const PERPLEXITY_API_ENDPOINT = 'https://api.perplexity.ai/chat/completions';

async function getDiffContent(octokit, owner, repo, pullNumber) {
  try {
    const response = await octokit.rest.pulls.get({
      owner,
      repo,
      pull_number: pullNumber,
      mediaType: {
        format: 'diff'
      }
    });
    return response.data;
  } catch (error) {
    throw new Error(`差分の取得に失敗しました: ${error.message}`);
  }
}

async function analyzeDependencies(diff) {
  try {
    const apiKey = core.getInput('perplexity-api-key');
    const response = await axios.post(PERPLEXITY_API_ENDPOINT, {
      model: "sonar-pro",
      messages: [
        {
          role: "system",
          content: `
Analyze the dependency changes in the provided diff for a project. Focus on security implications.
The diff content is:
\`\`\`diff
${diff}
\`\`\`

Identify each dependency change (added, removed, updated). For updates, specify the 'from' and 'to' versions.
For each changed dependency, provide a detailed security assessment:
1.  **Version Implications:** Analyze the semantic versioning (major, minor, patch) and its likely impact (breaking changes, new features, bug fixes).
2.  **Security Findings:**
    *   Research known CVEs or security advisories associated with BOTH the 'from' and 'to' versions. List relevant CVE IDs.
    *   Describe the nature of the vulnerabilities (e.g., RCE, XSS, DoS, data exposure).
    *   Identify potentially affected components or functionalities in the application.
    *   Provide evidence: Link to release notes, security advisories, or relevant code changes if possible.
3.  **Risk Score (0-10):** Assign a risk score based on the severity and likelihood of vulnerabilities fixed or introduced. 10 is highest risk.
4.  **Upgrade Recommendation (Japanese):** State clearly whether upgrading is recommended (例: 「強く推奨」、「推奨」、「検討」、「不要」).
5.  **Recommendations (Japanese):** Suggest specific actions (e.g., "Upgrade immediately", "Monitor closely", "Test thoroughly"). Mention alternatives if applicable. Note any specific monitoring needed.

Provide an **Overall Risk Assessment (Japanese):**
1.  **Overall Risk Score (0-10):** A single score summarizing the risk of all dependency changes.
2.  **Risk Level (Japanese):** Categorize the overall risk (例: 「低」、「中」、「高」、「緊急」).
3.  **Summary (Japanese):** Briefly explain the main risks and benefits of the changes.
4.  **Requires Immediate Action (Japanese):** State if immediate action is needed (例: 「あり」、「なし」).
5.  **Merge Recommendation (Japanese):** Recommend whether to merge the changes based on the security analysis (例: 「マージ可」、「注意してマージ」、「マージ前に対応必須」).

Respond ONLY with a JSON object containing two top-level keys: 'dependencies' (an array of objects, one for each changed dependency) and 'overall_risk_assessment'. Follow this structure precisely. Do not include any markdown formatting or introductory text.

JSON Structure:
{
  "dependencies": [
    {
      "name": "string",
      "change_type": "added|removed|updated",
      "version_change": { // Only if change_type is 'updated'
        "from": "string",
        "to": "string"
      },
      "version_implications": "string",
      "security_findings": {
        "severity": "string (e.g., high, medium, low, critical)", // Highest severity found
        "cves": ["string"],
        "description": "string",
        "affected_components": ["string"],
        "evidence": {
          "release_notes": "string",
          "implementation_changes": "string",
          "references": ["string"]
        }
      },
      "risk_score": "number (0-10)",
      "upgrade_recommendation_jp": "string", // Japanese text
      "recommendations_jp": { // Japanese text
        "actions": ["string"],
        "alternatives": ["string"],
        "additional_monitoring": ["string"]
      }
    }
    // ... more dependencies
  ],
  "overall_risk_assessment": {
    "overall_risk_score": "number (0-10)",
    "risk_level_jp": "string", // Japanese text
    "summary_jp": "string", // Japanese text
    "requires_immediate_action_jp": "string", // Japanese text
    "merge_recommendation_jp": "string" // Japanese text
  }
}
`
        },
        {
          role: "user",
          content: `Analyze this dependency change diff for security implications:\n\n${diff}`
        }
      ]
    }, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });

    try {
      // マークダウンフォーマットを削除
      let content = response.data.choices[0].message.content;
      // ```json や ``` などのマークダウン記号を削除
      content = content.replace(/^```json\s*\n|\n```\s*$/g, '');
      // 先頭と末尾の空白を削除
      content = content.trim();
      
      const analysisResult = JSON.parse(content);
      return analysisResult;
    } catch (error) {
      console.log('依存関係分析のレスポンスパースに失敗しました。生のレスポンス:', response.data.choices[0].message.content);
      throw new Error(`依存関係の分析に失敗しました: ${error.message}`);
    }
  } catch (error) {
    throw new Error(`依存関係の分析に失敗しました: ${error.message}`);
  }
}

async function analyzeVulnerabilities(diff, dependencies) {
  try {
    const apiKey = core.getInput('perplexity-api-key');
    const response = await axios.post(PERPLEXITY_API_ENDPOINT, {
      model: "sonar-pro",
      messages: [
        {
          role: "system",
          content: `
Analyze the provided code diff for potential security vulnerabilities and assess the security implications of the dependency changes listed.

Code Diff:
\`\`\`diff
${diff}
\`\`\`

Dependency Analysis Summary:
\`\`\`json
${JSON.stringify(dependencies, null, 2)}
\`\`\`

Perform a deep security analysis focusing on:
1.  **Code Changes Analysis:**
    *   Identify specific code patterns or anti-patterns related to security (e.g., improper input validation, hardcoded secrets, insecure API usage, race conditions, error handling flaws).
    *   Check for common vulnerability types (OWASP Top 10): Injection, Broken Authentication, Sensitive Data Exposure, XXE, Broken Access Control, Security Misconfiguration, XSS, Insecure Deserialization, Using Components with Known Vulnerabilities, Insufficient Logging & Monitoring.
    *   Analyze changes in authentication, authorization, session management, and data handling logic.
2.  **Dependency Interaction:** Assess how the code changes interact with the updated dependencies. Are new dependency features used securely? Are vulnerabilities in dependencies mitigated or potentially exposed by the code changes?
3.  **Vulnerability Assessment:** For each identified potential vulnerability:
    *   Assign a **Severity** (critical, high, medium, low).
    *   Assign a **Risk Score (0-10)** based on likelihood and impact. 10 is highest risk.
    *   Provide a detailed **Description** of the vulnerability.
    *   Include **Technical Details:** Affected code snippets, attack vectors, impact analysis, root cause.
    *   Provide **Evidence:** Code location (file path, line numbers), proof-of-concept ideas (if applicable), related CVEs (if the pattern matches a known type).
    *   Suggest **Mitigation:** Recommended fixes, alternative solutions, security best practices.
4.  **Overall Assessment (Japanese):**
    *   **Overall Risk Score (0-10):** Combine findings from code changes and dependency interactions.
    *   **Merge Recommendation (Japanese):** Based on the vulnerabilities found (例: 「マージ可」、「注意してマージ」、「マージ前に対応必須」).
    *   Provide **Analysis Metadata:** Scan coverage, confidence level, limitations of the analysis.

Respond ONLY with a JSON object. Do not include any markdown formatting or introductory text.

JSON Structure:
{
  "vulnerabilities": [
    {
      "severity": "critical|high|medium|low",
      "risk_score": "number (0-10)",
      "type": "string (e.g., Injection, XSS, Dependency Issue, Misconfiguration)",
      "description": "string",
      "technical_details": {
        "affected_code": "string",
        "attack_vectors": ["string"],
        "impact_analysis": "string",
        "root_cause": "string"
      },
      "evidence": {
        "code_location": "string",
        "proof_of_concept": "string",
        "related_cves": ["string"]
      },
      "mitigation": {
        "recommended_fix_jp": "string", // Japanese text
        "alternative_solutions_jp": ["string"], // Japanese text
        "security_best_practices_jp": ["string"] // Japanese text
      }
    }
    // ... more vulnerabilities
  ],
  "overall_risk_assessment": {
      "overall_risk_score": "number (0-10)",
      "merge_recommendation_jp": "string" // Japanese text
  },
  "analysis_metadata": {
    "scan_coverage": ["string"],
    "confidence_level": "high|medium|low",
    "limitations": ["string"]
  }
}
`
        },
        {
          role: "user",
          content: `Analyze this code diff for security vulnerabilities:\n\n${diff}`
        }
      ]
    }, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });

    try {
      // マークダウンフォーマットを削除
      let content = response.data.choices[0].message.content;
      // ```json や ``` などのマークダウン記号を削除
      content = content.replace(/^```json\s*\n|\n```\s*$/g, '');
      // 先頭と末尾の空白を削除
      content = content.trim();
      
      const analysisResult = JSON.parse(content);
      if (!analysisResult.vulnerabilities || !Array.isArray(analysisResult.vulnerabilities)) {
        console.log('予期しない形式のレスポンス:', content);
        return {
          vulnerabilities: [],
          analysis_metadata: analysisResult.analysis_metadata || {
            scan_coverage: ['Limited scan due to response format issues'],
            confidence_level: 'low',
            limitations: ['Response format did not match expected structure']
          }
        };
      }
      return analysisResult;
    } catch (parseError) {
      console.log('APIレスポンスのパースに失敗しました。生のレスポンス:', response.data.choices[0].message.content);
      return {
        vulnerabilities: [],
        analysis_metadata: {
          scan_coverage: ['Limited scan due to parse error'],
          confidence_level: 'low',
          limitations: ['Failed to parse API response']
        }
      };
    }
  } catch (error) {
    throw new Error(`脆弱性スキャンに失敗しました: ${error.message}`);
  }
}

async function run() {
  try {
    // 入力パラメータを取得
    const severityLevel = core.getInput('severity-level');
    const scanDirectory = core.getInput('scan-directory');
    const token = core.getInput('github-token');

    // GitHub APIクライアントを初期化
    const octokit = github.getOctokit(token);
    const context = github.context;

    // PRの場合、情報を表示
    if (context.eventName === 'pull_request') {
      const pullRequest = context.payload.pull_request;
      try {
        // PR差分を取得
        const diff = await getDiffContent(
          octokit,
          context.repo.owner,
          context.repo.repo,
          pullRequest.number
        );
        console.log('PR差分の取得完了');

        // 依存関係の分析
        const dependencyAnalysis = await analyzeDependencies(diff);
        console.log('依存関係の分析結果:', JSON.stringify(dependencyAnalysis, null, 2));

        // 脆弱性スキャン
        const vulnerabilityResults = await analyzeVulnerabilities(diff, dependencyAnalysis.dependencies);
        console.log('脆弱性スキャン結果:', JSON.stringify(vulnerabilityResults, null, 2));

        // 結果の処理
        let hasHighSeverity = false;
        let securityReport = '## セキュリティ分析レポート\n\n';

        // 依存関係の分析結果を追加
        if (dependencyAnalysis?.dependencies) {
          securityReport += '### 依存関係の分析\n\n';
          
          for (const dep of dependencyAnalysis.dependencies) {
            securityReport += `#### ${dep.name}\n`;
            if (dep.version_change) {
              securityReport += `- バージョン変更: ${dep.version_change.from} → ${dep.version_change.to}\n`;
            }
            if (dep.security_findings) {
              securityReport += `- 重要度: ${dep.security_findings.severity}\n`;
              if (dep.security_findings.cves && dep.security_findings.cves.length > 0) {
                securityReport += `- 関連するCVE: ${dep.security_findings.cves.join(', ')}\n`;
              }
              securityReport += `- 詳細: ${dep.security_findings.description}\n`;
              if (dep.security_findings.affected_components) {
                securityReport += `- 影響を受けるコンポーネント: ${dep.security_findings.affected_components.join(', ')}\n`;
              }
              if (dep.security_findings.evidence) {
                securityReport += '- 証拠:\n';
                securityReport += `  - リリースノート: ${dep.security_findings.evidence.release_notes}\n`;
                securityReport += `  - 実装の変更: ${dep.security_findings.evidence.implementation_changes}\n`;
              }
            }
            if (dep.recommendations) {
              securityReport += '\n推奨される対応:\n';
              if (dep.recommendations.actions) {
                for (const action of dep.recommendations.actions) {
                  securityReport += `- ${action}\n`;
                }
              }
            }
            securityReport += '\n';
          }

          if (dependencyAnalysis.overall_risk_assessment) {
            securityReport += '### 全体的なリスク評価\n';
            securityReport += `- リスクレベル: ${dependencyAnalysis.overall_risk_assessment.risk_level_jp}\n`;
            securityReport += `- 概要: ${dependencyAnalysis.overall_risk_assessment.summary_jp}\n`;
            securityReport += `- 即時対応の必要性: ${dependencyAnalysis.overall_risk_assessment.requires_immediate_action_jp === 'あり' ? 'あり' : 'なし'}\n\n`;
          }
        }

        // 脆弱性スキャン結果を追加
        if (vulnerabilityResults.vulnerabilities) {
          securityReport += '### 脆弱性スキャン結果\n\n';
          
          for (const vuln of vulnerabilityResults.vulnerabilities) {
            const severityLevels = ['low', 'medium', 'high', 'critical'];
            const severityIndex = severityLevels.indexOf(severityLevel.toLowerCase());
            if (severityLevels.indexOf(vuln.severity?.toLowerCase()) >= severityIndex) {
              hasHighSeverity = true;
            }
            
            securityReport += `#### ${vuln.type || '未分類の脆弱性'}\n`;
            securityReport += `- 重要度: ${vuln.severity}\n`;
            securityReport += `- 説明: ${vuln.description}\n`;

            if (vuln.technical_details) {
              securityReport += '- 技術的詳細:\n';
              securityReport += `  - 影響を受けるコード: ${vuln.technical_details.affected_code}\n`;
              if (vuln.technical_details.attack_vectors) {
                securityReport += `  - 攻撃ベクトル: ${vuln.technical_details.attack_vectors.join(', ')}\n`;
              }
              securityReport += `  - 影響分析: ${vuln.technical_details.impact_analysis}\n`;
              securityReport += `  - 根本原因: ${vuln.technical_details.root_cause}\n`;
            }

            if (vuln.mitigation) {
              securityReport += '- 対策:\n';
              securityReport += `  - 推奨される修正: ${vuln.mitigation.recommended_fix_jp}\n`;
              if (vuln.mitigation.security_best_practices_jp) {
                securityReport += `  - セキュリティベストプラクティス: ${vuln.mitigation.security_best_practices_jp.join(', ')}\n`;
              }
            }

            securityReport += '\n';
          }

          if (vulnerabilityResults.analysis_metadata) {
            securityReport += '### 分析メタデータ\n';
            securityReport += `- スキャン範囲: ${vulnerabilityResults.analysis_metadata.scan_coverage.join(', ')}\n`;
            securityReport += `- 信頼度: ${vulnerabilityResults.analysis_metadata.confidence_level}\n`;
            if (vulnerabilityResults.analysis_metadata.limitations) {
              securityReport += `- 制限事項: ${vulnerabilityResults.analysis_metadata.limitations.join(', ')}\n`;
            }
          }
        }

        // コメントとして結果を投稿
        await octokit.rest.issues.createComment({
          owner: context.repo.owner,
          repo: context.repo.repo,
          issue_number: pullRequest.number,
          body: securityReport
        });

        if (hasHighSeverity) {
          core.setFailed(`設定された重要度レベル(${severityLevel})以上の脆弱性が検出されました`);
          return;
        }

        core.notice('スキャン完了: 重大な脆弱性は見つかりませんでした');
        core.setOutput('result', JSON.stringify({
          dependencyAnalysis,
          vulnerabilityResults,
          conclusion: '脆弱性は検出されませんでした'
        }));
      } catch (error) {
        console.error('スキャン中にエラーが発生しました:', error);
        core.setFailed(`スキャンに失敗しました: ${error.message}`);
      }
    } else {
      console.log(`現在のイベントタイプ: ${context.eventName} (PRイベントではありません)`);
      core.setOutput('result', JSON.stringify({
        status: 'skipped',
        reason: 'PRイベント以外ではスキャンは実行されません'
      }));
    }
  } catch (error) {
    core.setFailed(`アクションが失敗しました: ${error.message}`);
  }
}

run(); 