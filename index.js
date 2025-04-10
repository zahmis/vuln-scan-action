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
    *   Describe the nature of the vulnerabilities (e.g., RCE, XSS, DoS, data exposure) in JAPANESE.
    *   Identify potentially affected components or functionalities in the application.
    *   Provide evidence: Link to release notes, security advisories, or relevant code changes if possible.
3.  **Risk Score (0-10):** Assign a risk score (NUMBER) based on the severity and likelihood of vulnerabilities fixed or introduced. 10 is highest risk.
4.  **Upgrade Recommendation (Japanese):** State clearly IN JAPANESE whether upgrading is recommended (例: 「強く推奨」、「推奨」、「検討」、「不要」).
5.  **Recommendations (Japanese):** Suggest specific actions IN JAPANESE (e.g., \"直ちにアップグレード\", \"注意深く監視\", \"徹底的にテスト\"). Mention alternatives if applicable. Note any specific monitoring needed.

Provide an **Overall Risk Assessment (Japanese):**
1.  **Overall Risk Score (0-10):** A single score (NUMBER) summarizing the risk of all dependency changes.
2.  **Risk Level (Japanese):** Categorize the overall risk IN JAPANESE (例: 「低」、「中」、「高」、「緊急」).
3.  **Summary (Japanese):** Briefly explain the main risks and benefits of the changes IN JAPANESE.
4.  **Requires Immediate Action (Japanese):** State IN JAPANESE if immediate action is needed (例: 「あり」、「なし」).
5.  **Merge Recommendation (Japanese):** Recommend IN JAPANESE whether to merge the changes based on the security analysis (例: 「マージ可」、「注意してマージ」、「マージ前に対応必須」).

Respond ONLY with a valid JSON object containing two top-level keys: 'dependencies' (an array of objects, one for each changed dependency) and 'overall_risk_assessment'. Follow this structure precisely. Do not include any markdown formatting or introductory text.

JSON Structure:
{
  "dependencies": [
    {
      "name": "string",
      "change_type": "added|removed|updated",
      "version_change": { "from": "string", "to": "string" },
      "version_implications": "string",
      "security_findings": {
        "severity": "string", "cves": ["string"], "description_jp": "string", "affected_components": ["string"],
        "evidence": { "release_notes": "string", "implementation_changes": "string", "references": ["string"] }
      },
      "risk_score": number,
      "upgrade_recommendation_jp": "string",
      "recommendations_jp": { "actions": ["string"], "alternatives": ["string"], "additional_monitoring": ["string"] }
    }
  ],
  "overall_risk_assessment": {
    "overall_risk_score": number,
    "risk_level_jp": "string", "summary_jp": "string", "requires_immediate_action_jp": "string", "merge_recommendation_jp": "string"
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
      let content = response.data.choices[0].message.content;
      content = content.replace(/^```json\s*\n|\n```\s*$/g, '').trim();
      const analysisResult = JSON.parse(content);

      if (!analysisResult || typeof analysisResult !== 'object' || !analysisResult.dependencies || !Array.isArray(analysisResult.dependencies) || !analysisResult.overall_risk_assessment) {
        throw new Error('Invalid JSON structure received for dependencies.');
      }

      // Ensure scores are numbers, defaulting to 0
      analysisResult.overall_risk_assessment.overall_risk_score = Number(analysisResult.overall_risk_assessment.overall_risk_score) || 0;
      analysisResult.dependencies.forEach(dep => {
        dep.risk_score = Number(dep.risk_score) || 0;
      });

      return analysisResult;
    } catch (parseError) {
      console.error('依存関係分析のレスポンスパースに失敗:', parseError, 'Raw response:', response.data.choices[0]?.message?.content);
      // Return default structure on parse error
      return {
        dependencies: [],
        overall_risk_assessment: { overall_risk_score: 0, risk_level_jp: '不明', summary_jp: 'APIレスポンスの解析に失敗しました。', requires_immediate_action_jp: '不明', merge_recommendation_jp: '判断不可' }
      };
    }
  } catch (apiError) {
    console.error(`依存関係分析API呼び出し中にエラー: ${apiError.message}`);
    // Return default structure on API call error
    return {
      dependencies: [],
      overall_risk_assessment: { overall_risk_score: 0, risk_level_jp: '不明', summary_jp: '依存関係分析APIへの接続または処理中にエラーが発生しました。', requires_immediate_action_jp: '不明', merge_recommendation_jp: '判断不可' }
    };
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

Dependency Analysis Summary (for context):
\`\`\`json
${JSON.stringify(dependencies, null, 2)}
\`\`\`

Perform a deep security analysis focusing on:
1.  **Code Changes Analysis:** Identify security-related code patterns/anti-patterns, check for common vulnerability types (OWASP Top 10), analyze changes in auth/data handling.
2.  **Dependency Interaction:** Assess how code changes interact with updated dependencies.
3.  **Vulnerability Assessment:** For each potential vulnerability found:
    *   Assign **Severity** (critical, high, medium, low).
    *   Assign **Risk Score (0-10)** (NUMBER).
    *   Provide detailed **Description** IN JAPANESE.
    *   Include **Technical Details** (affected code, attack vectors, impact, root cause).
    *   Provide **Evidence** (code location, PoC ideas, related CVEs).
    *   Suggest **Mitigation** (recommended fixes, alternatives, best practices) IN JAPANESE.
4.  **Overall Assessment (Japanese):**
    *   **Overall Risk Score (0-10)** (NUMBER) combining code and dependency findings.
    *   **Merge Recommendation (Japanese)** (例: 「マージ可」、「注意してマージ」、「マージ前に対応必須」).
    *   Provide **Analysis Metadata** (scan coverage, confidence, limitations).

Respond ONLY with a valid JSON object. Do not include markdown formatting.

JSON Structure:
{
  "vulnerabilities": [
    {
      "severity": "critical|high|medium|low",
      "risk_score": number,
      "type": "string",
      "description_jp": "string",
      "technical_details": { "affected_code": "string", "attack_vectors": ["string"], "impact_analysis": "string", "root_cause": "string" },
      "evidence": { "code_location": "string", "proof_of_concept": "string", "related_cves": ["string"] },
      "mitigation": { "recommended_fix_jp": "string", "alternative_solutions_jp": ["string"], "security_best_practices_jp": ["string"] }
    }
  ],
  "overall_risk_assessment": { "overall_risk_score": number, "merge_recommendation_jp": "string" },
  "analysis_metadata": { "scan_coverage": ["string"], "confidence_level": "high|medium|low", "limitations": ["string"] }
}
`
        },
        {
          role: "user",
          content: `Analyze this code diff for security vulnerabilities, considering the provided dependency context:\n\n${diff}`
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
      let content = response.data.choices[0].message.content;
      content = content.replace(/^```json\s*\n|\n```\s*$/g, '').trim();
      const analysisResult = JSON.parse(content);

      if (!analysisResult || typeof analysisResult !== 'object' || !analysisResult.vulnerabilities || !Array.isArray(analysisResult.vulnerabilities) || !analysisResult.analysis_metadata || !analysisResult.overall_risk_assessment) {
        throw new Error('Invalid JSON structure received for vulnerabilities.');
      }

      // Ensure scores are numbers
      if(analysisResult.overall_risk_assessment) {
          analysisResult.overall_risk_assessment.overall_risk_score = Number(analysisResult.overall_risk_assessment.overall_risk_score) || 0;
      }
      analysisResult.vulnerabilities.forEach(vuln => {
          vuln.risk_score = Number(vuln.risk_score) || 0;
      });

      return analysisResult;
    } catch (parseError) {
      console.error('脆弱性スキャンAPIレスポンスのパースに失敗:', parseError, 'Raw response:', response.data.choices[0]?.message?.content);
      // Return default structure on parse error
      return {
        vulnerabilities: [],
        overall_risk_assessment: { overall_risk_score: 0, merge_recommendation_jp: '判断不可' },
        analysis_metadata: { scan_coverage: ['Limited scan due to parse error'], confidence_level: 'low', limitations: ['Failed to parse API response'] }
      };
    }
  } catch (apiError) {
    console.error(`脆弱性スキャンAPI呼び出し中にエラー: ${apiError.message}`);
    // Return default structure on API call error
    return {
      vulnerabilities: [],
      overall_risk_assessment: { overall_risk_score: 0, merge_recommendation_jp: '判断不可' },
      analysis_metadata: { scan_coverage: ['API call failed'], confidence_level: 'low', limitations: ['Error connecting to or processing vulnerability scan API'] }
    };
  }
}

// Helper to get severity score (higher number is more severe)
function getSeverityScore(severity) {
    const lowerSeverity = severity?.toLowerCase();
    switch(lowerSeverity) {
        case 'critical': return 4;
        case 'high': return 3;
        case 'medium': return 2;
        case 'low': return 1;
        default: return 0;
    }
}

// Function to generate the security report in the new format
function generateSecurityReport(dependencyAnalysis, vulnerabilityResults, severityLevel) {
  let securityReport = '';
  let finalOverallRiskScore = 0;
  let finalMergeRecommendation = '判断不可';
  let topRecommendations = [];

  // --- 1. Process Data & Calculate Overall Scores ---

  // Dependency Analysis Data
  const depOverallRisk = dependencyAnalysis?.overall_risk_assessment;
  const depOverallScore = depOverallRisk?.overall_risk_score ?? 0; // Default to 0 if undefined
  let depMergeRec = depOverallRisk?.merge_recommendation_jp ?? '判断不可';
  const depImmediateAction = depOverallRisk?.requires_immediate_action_jp === 'あり';

  // Extract top recommendations from dependencies
  if (dependencyAnalysis?.dependencies) {
      dependencyAnalysis.dependencies.forEach(dep => {
          const actions = dep.recommendations_jp?.actions;
          if (actions && actions.length > 0) {
               const depRiskScore = dep.risk_score ?? 0; // Default to 0
               // Prioritize recommendations for high-risk dependencies
               if (depRiskScore >= 7 || getSeverityScore(dep.security_findings?.severity) >= getSeverityScore('high')) {
                   topRecommendations.push(`**[依存関係] ${dep.name}:** ${actions[0]}`);
               }
          }
      });
  }
  if (depImmediateAction && !topRecommendations.some(rec => rec.includes('即時対応'))) {
      topRecommendations.unshift('**[依存関係]** 分析結果に基づき、**即時対応が必要**です。');
  }

  // Vulnerability Analysis Data
  const vulnOverallRisk = vulnerabilityResults?.overall_risk_assessment;
  const vulnOverallScore = vulnOverallRisk?.overall_risk_score ?? 0; // Default to 0
  let vulnMergeRec = vulnOverallRisk?.merge_recommendation_jp ?? '判断不可';
  let highSeverityVulnsExist = false;

  // Extract top recommendations from vulnerabilities
  if (vulnerabilityResults?.vulnerabilities && vulnerabilityResults.vulnerabilities.length > 0) {
      vulnerabilityResults.vulnerabilities.forEach(vuln => {
          const vulnRiskScore = vuln.risk_score ?? 0; // Default to 0
          const severityScore = getSeverityScore(vuln.severity);
          if (severityScore >= getSeverityScore('high')) { // Consider high or critical as high severity
              highSeverityVulnsExist = true;
          }
          if (vuln.mitigation?.recommended_fix_jp) {
              // Prioritize recommendations for high-risk vulnerabilities
              if (vulnRiskScore >= 7 || severityScore >= getSeverityScore('high')) {
                 topRecommendations.push(`**[脆弱性] ${vuln.type || '不明'}:** ${vuln.mitigation.recommended_fix_jp}`);
              }
          }
      });
  }

  // Determine Final Overall Score and Merge Recommendation
  finalOverallRiskScore = Math.max(depOverallScore, vulnOverallScore);

  // Prioritize stricter merge recommendations
  const mergeOrder = ['マージ前に対応必須', '注意してマージ', 'マージ可', '判断不可'];
  const depRecIndex = mergeOrder.indexOf(depMergeRec);
  const vulnRecIndex = mergeOrder.indexOf(vulnMergeRec);

  // Choose the stricter recommendation (lower index in mergeOrder)
  if (depRecIndex !== -1 && vulnRecIndex !== -1) {
      finalMergeRecommendation = mergeOrder[Math.min(depRecIndex, vulnRecIndex)];
  } else if (depRecIndex !== -1) { // Only dep recommendation is valid
      finalMergeRecommendation = depMergeRec;
  } else if (vulnRecIndex !== -1) { // Only vuln recommendation is valid
      finalMergeRecommendation = vulnMergeRec;
  }
  // Override: If high severity vulns exist, recommendation should be at least '注意してマージ'
  if (highSeverityVulnsExist) {
      const currentRecIndex = mergeOrder.indexOf(finalMergeRecommendation);
      const cautionIndex = mergeOrder.indexOf('注意してマージ');
      if (currentRecIndex > cautionIndex) { // If current is 'マージ可' or '判断不可'
          finalMergeRecommendation = '注意してマージ';
      }
  }


  // --- 2. Build the Report String ---

  // Report Summary
  securityReport += '## セキュリティ分析レポート (概要)\n\n';
  securityReport += `**総合リスク評価:** ${finalOverallRiskScore} / 10 点\n`;
  securityReport += `**マージ判断:** ${finalMergeRecommendation}\n`;

  if (topRecommendations.length > 0) {
      securityReport += '**推奨アクション (上位抜粋):**\n';
      // Sort recommendations: Immediate action first, then by type
      topRecommendations.sort((a, b) => {
          if (a.includes('即時対応')) return -1;
          if (b.includes('即時対応')) return 1;
          if (a.startsWith('**[依存関係]') && !b.startsWith('**[依存関係]')) return -1;
          if (!a.startsWith('**[依存関係]') && b.startsWith('**[依存関係]')) return 1;
          return 0;
      });
      topRecommendations.slice(0, 5).forEach(rec => { // Show up to 5 recommendations
          securityReport += `- ${rec}\n`;
      });
  }
  securityReport += '\n---\n\n';

  // Detailed Dependency Analysis
  securityReport += '## 変更された依存関係の詳細\n\n';
  if (dependencyAnalysis?.dependencies && dependencyAnalysis.dependencies.length > 0) {
    dependencyAnalysis.dependencies.forEach((dep, index) => {
      securityReport += `### ${index + 1}. \`${dep.name}\`\n`;
      if (dep.change_type === 'updated') {
        securityReport += `*   **バージョン変更:** \`${dep.version_change?.from}\` → \`${dep.version_change?.to}\`\n`;
      } else {
         securityReport += `*   **変更タイプ:** ${dep.change_type}\n`;
         if(dep.change_type === 'added' && dep.version_change?.to) {
            securityReport += `*   **追加バージョン:** \`${dep.version_change.to}\`\n`;
         }
      }
      const depRiskScoreText = dep.risk_score !== undefined ? `${dep.risk_score} / 10 点` : 'N/A';
      securityReport += `*   **リスクスコア:** ${depRiskScoreText}\n`;
      if (dep.security_findings) {
            const findings = dep.security_findings;
            securityReport += `*   **主な変更/修正点 (重要度: ${findings.severity || '不明'}):**\n`;
            securityReport += `    *   ${findings.description_jp || findings.description || '詳細不明'}\n`; // Fallback to english description if jp missing
            if (findings.cves && findings.cves.length > 0) {
                 securityReport += `    *   関連CVE/アドバイザリ: ${findings.cves.join(', ')}\n`;
            }
      }
      securityReport += `*   **バージョンアップ推奨度:** ${dep.upgrade_recommendation_jp || '情報なし'}\n`;
      if (dep.recommendations_jp) {
           securityReport += `*   **推奨アクション/考慮事項:**\n`;
           if(dep.recommendations_jp.actions && dep.recommendations_jp.actions.length > 0) {
                securityReport += `    *   アクション: ${dep.recommendations_jp.actions.join(', ')}\n`;
           }
           if(dep.recommendations_jp.additional_monitoring && dep.recommendations_jp.additional_monitoring.length > 0) {
                 securityReport += `    *   追加モニタリング: ${dep.recommendations_jp.additional_monitoring.join(', ')}\n`;
           }
           if(dep.recommendations_jp.alternatives && dep.recommendations_jp.alternatives.length > 0) {
                 securityReport += `    *   代替案: ${dep.recommendations_jp.alternatives.join(', ')}\n`;
           }
      }
      securityReport += '\n';
    });
  } else {
      securityReport += '変更された依存関係はありませんでした。\n';
  }
  securityReport += '\n---\n\n';

  // Detailed Vulnerability Analysis
  securityReport += '## 検出された脆弱性・懸念事項\n\n';
  if (vulnerabilityResults?.vulnerabilities && vulnerabilityResults.vulnerabilities.length > 0) {
        vulnerabilityResults.vulnerabilities.forEach((vuln, index) => {
            const vulnRiskScoreText = vuln.risk_score !== undefined ? `${vuln.risk_score} / 10 点` : 'N/A';
            securityReport += `### ${index + 1}. ${vuln.type || '未分類の問題'}\n`;
            securityReport += `*   **リスクスコア:** ${vulnRiskScoreText} (重要度: ${vuln.severity || 'N/A'})\\n`;
            securityReport += `*   **説明:** ${vuln.description_jp || vuln.description || '詳細なし'}\n`; // Fallback to english
             if (vuln.mitigation) {
                 securityReport += `*   **推奨される対策:** ${vuln.mitigation.recommended_fix_jp || '情報なし'}\n`;
                 if (vuln.mitigation.security_best_practices_jp && vuln.mitigation.security_best_practices_jp.length > 0) {
                     securityReport += `    *   ベストプラクティス: ${vuln.mitigation.security_best_practices_jp.join(', ')}\n`;
                 }
                 if (vuln.mitigation.alternative_solutions_jp && vuln.mitigation.alternative_solutions_jp.length > 0) {
                     securityReport += `    *   代替ソリューション: ${vuln.mitigation.alternative_solutions_jp.join(', ')}\n`;
                 }
             }
             if (vuln.evidence?.code_location) {
                 securityReport += `*   コード箇所: ${vuln.evidence.code_location}\n`;
             }
            securityReport += '\n';
        });
  } else {
        securityReport += '検出された脆弱性・懸念事項はありませんでした。\n';
  }
  securityReport += '\n---\n\n';

  // Metadata
  securityReport += '**分析メタデータ (参考)**\n';
  const meta = vulnerabilityResults?.analysis_metadata || dependencyAnalysis?.analysis_metadata; // Use vuln metadata if available
  if (meta) {
        securityReport += `*   **スキャン範囲:** ${meta.scan_coverage ? meta.scan_coverage.join(', ') : '不明'}\n`;
        securityReport += `*   **信頼度:** ${meta.confidence_level || '不明'}\n`;
        securityReport += `*   **制限事項:** ${meta.limitations ? meta.limitations.join(', ') : 'なし'}\n`;
  } else {
        securityReport += '*   メタデータは利用できませんでした。\n';
  }

  // --- 3. Set Action Outputs & Failure Condition ---
  console.log(`レポート生成完了。総合リスクスコア: ${finalOverallRiskScore}, マージ判断: ${finalMergeRecommendation}`);

  // Set action output
  core.setOutput('analysis_report', securityReport);
  core.setOutput('overall_risk_score', finalOverallRiskScore);
  core.setOutput('merge_recommendation', finalMergeRecommendation);

  // Fail the action based on score or merge recommendation
  let shouldFail = false;
  // Fail if score is high enough (e.g., 7+) OR if recommendation requires action before merge
  if (finalOverallRiskScore >= 7) {
      console.log(`リスクスコア (${finalOverallRiskScore}) が閾値 (7) 以上です。`);
      shouldFail = true;
  }
  if (finalMergeRecommendation === 'マージ前に対応必須') {
       console.log('マージ前に対応が必要と判断されました。');
       shouldFail = true;
  }

  // Optionally fail based on severity threshold input
  let maxSeverityFound = 'low';
  let maxSeverityScore = 0;
  if(dependencyAnalysis?.dependencies) {
       dependencyAnalysis.dependencies.forEach(d => {
           const currentScore = getSeverityScore(d.security_findings?.severity);
            if(currentScore > maxSeverityScore) {
                maxSeverityScore = currentScore;
                maxSeverityFound = d.security_findings.severity;
            }
       });
  }
  if(vulnerabilityResults?.vulnerabilities) {
        vulnerabilityResults.vulnerabilities.forEach(v => {
            const currentScore = getSeverityScore(v.severity);
             if(currentScore > maxSeverityScore) {
                 maxSeverityScore = currentScore;
                 maxSeverityFound = v.severity;
             }
        });
  }
  const thresholdSeverityScore = getSeverityScore(severityLevel || 'medium');

  if (maxSeverityScore >= thresholdSeverityScore) {
      console.log(`検出された最大重要度 (${maxSeverityFound || 'N/A'}) が指定された閾値 (${severityLevel || 'medium'}) 以上です。`);
      // Uncomment below if high severity finding should always fail the check
      // shouldFail = true;
  }


  if (shouldFail) {
    // Provide a more informative failure message
    core.setFailed(`セキュリティレビューが必要です。総合リスクスコア: ${finalOverallRiskScore}/10。マージ判断: ${finalMergeRecommendation}。詳細はレポートを確認してください。`);
    core.saveState('isFailed', 'true'); // Save state to prevent notice message
  }

  return securityReport; // Return the generated report string
}

async function run() {
  try {
    // 入力パラメータを取得
    const severityLevel = core.getInput('severity-level');
    const token = core.getInput('github-token');

    // GitHub APIクライアントを初期化
    const octokit = github.getOctokit(token);
    const context = github.context;

    // PRの場合のみ実行
    if (context.eventName === 'pull_request') {
      const pullRequest = context.payload.pull_request;
      if (!pullRequest) {
          core.setFailed('Pull request contextが見つかりません。');
          return;
      }
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
        console.log('依存関係の分析結果 (生):', JSON.stringify(dependencyAnalysis, null, 2));

        // 脆弱性スキャン (依存関係の結果を渡す)
        const vulnerabilityResults = await analyzeVulnerabilities(diff, dependencyAnalysis?.dependencies || []);
        console.log('脆弱性スキャン結果 (生):', JSON.stringify(vulnerabilityResults, null, 2));

        // レポート生成
        const securityReport = generateSecurityReport(dependencyAnalysis, vulnerabilityResults, severityLevel);
        console.log('\n--- 生成されたセキュリティレポート ---');
        console.log(securityReport);
        console.log('--- レポートここまで ---');

        // コメントとして結果を投稿
        console.log('GitHub PRにコメントを投稿します...');
        await octokit.rest.issues.createComment({
          owner: context.repo.owner,
          repo: context.repo.repo,
          issue_number: pullRequest.number,
          body: securityReport
        });
        console.log('コメント投稿完了。');

        // Check if the action has failed (setFailed was called)
        // Use a saved state because core.getStatus() might not be immediately updated
        if (process.env.GITHUB_ACTIONS === 'true' && core.getState('isFailed') !== 'true') {
             core.notice('スキャン完了。詳細はPRコメントを確認してください。');
        }

      } catch (error) {
        console.error('スキャンまたはレポート生成中にエラーが発生しました:', error);
        // Try to post a failure comment if possible
        try {
            await octokit.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.payload.pull_request?.number || 0, // Use optional chaining and fallback
              body: `セキュリティスキャンの実行中にエラーが発生しました。\n\n\`\`\`\n${error.message}\n\`\`\`\n詳細はActionsのログを確認してください。`
            });
        } catch (commentError) {
            console.error('失敗コメントの投稿中にエラー:', commentError);
        }
        core.setFailed(`スキャン実行中にエラーが発生しました: ${error.message}`);
      }
    } else {
      console.log(`現在のイベントタイプ: ${context.eventName} (PRイベントではありません)。スキャンをスキップします。`);
      core.setOutput('status', 'skipped');
    }
  } catch (error) {
    core.setFailed(`アクションの初期化または実行中に致命的なエラーが発生しました: ${error.message}`);
  }
}

run(); 