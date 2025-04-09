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
          content: `You are a security expert specializing in dependency analysis and vulnerability assessment. Your task is to:

1. Identify all dependency changes in the provided diff
2. For each dependency:
   - Compare version changes and analyze semantic versioning implications
   - Research and cite specific CVEs or security advisories
   - Review release notes, changelogs, and relevant GitHub issues
   - Analyze potential security impact of the changes
   - Check for transitive dependency conflicts or vulnerabilities
   - Examine implementation changes that might affect security

3. Provide a comprehensive security assessment including:
   - Direct security implications
   - Indirect security risks (e.g., dependency chain issues)
   - Compatibility concerns
   - Specific code areas that need review
   - Concrete mitigation recommendations

Return ONLY the JSON data without any markdown formatting or code block indicators. The response should start directly with { and end with }:
{
  "dependencies": [
    {
      "name": "package name",
      "version_change": {
        "from": "old version",
        "to": "new version"
      },
      "security_findings": {
        "severity": "critical|high|medium|low",
        "cves": ["CVE-ID"],
        "description": "Detailed security impact description",
        "affected_components": ["specific components or features affected"],
        "evidence": {
          "release_notes": "relevant release note excerpts",
          "implementation_changes": "security-relevant code changes",
          "references": ["links to issues, PRs, or discussions"]
        }
      },
      "recommendations": {
        "actions": ["specific actions to take"],
        "alternatives": ["alternative solutions if applicable"],
        "additional_monitoring": ["areas or components to monitor"]
      }
    }
  ],
  "overall_risk_assessment": {
    "risk_level": "critical|high|medium|low",
    "summary": "Overall security impact summary",
    "requires_immediate_action": boolean
  }
}`
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

async function analyzeVulnerabilities(diff, severityLevel) {
  try {
    const apiKey = core.getInput('perplexity-api-key');
    const response = await axios.post(PERPLEXITY_API_ENDPOINT, {
      model: "sonar-pro",
      messages: [
        {
          role: "system",
          content: `You are a security vulnerability analyzer with deep expertise in code review and security assessment. Your task is to:

1. Perform deep analysis of code changes:
   - Identify potential security vulnerabilities
   - Analyze code patterns and anti-patterns
   - Review API usage and security implications
   - Check for common vulnerability types (OWASP Top 10, etc.)
   - Examine error handling and input validation
   - Assess authentication and authorization changes

2. Consider broader security context:
   - Impact on existing security controls
   - Integration points and trust boundaries
   - Data flow security implications
   - Configuration changes affecting security
   - Compliance implications

3. Provide detailed vulnerability assessment with severity level ${severityLevel} or higher.

Return ONLY the JSON data without any markdown formatting or code block indicators. The response should start directly with { and end with }:
{
  "vulnerabilities": [
    {
      "severity": "critical|high|medium|low",
      "type": "vulnerability category (e.g., XSS, CSRF, etc.)",
      "description": "Detailed description of the vulnerability",
      "technical_details": {
        "affected_code": "specific code snippets or patterns",
        "attack_vectors": ["possible attack scenarios"],
        "impact_analysis": "potential security impact",
        "root_cause": "underlying security issue"
      },
      "evidence": {
        "code_location": "file and line numbers",
        "proof_of_concept": "how the vulnerability could be exploited",
        "related_cves": ["similar CVEs if applicable"]
      },
      "mitigation": {
        "recommended_fix": "specific code changes or security controls",
        "alternative_solutions": ["other possible fixes"],
        "security_best_practices": ["relevant security guidelines"]
      },
      "risk_assessment": {
        "likelihood": "high|medium|low",
        "impact": "high|medium|low",
        "exploit_complexity": "high|medium|low"
      }
    }
  ],
  "analysis_metadata": {
    "scan_coverage": ["areas analyzed"],
    "confidence_level": "high|medium|low",
    "limitations": ["any limitations in the analysis"]
  }
}`
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
        console.log('依存関係の分析結果:', dependencyAnalysis);

        // 脆弱性スキャン
        const vulnerabilityResults = await analyzeVulnerabilities(diff, severityLevel);
        console.log('脆弱性スキャン結果:', vulnerabilityResults);

        // 結果の処理
        let hasHighSeverity = false;
        let securityReport = '## セキュリティ分析レポート\n\n';

        // 依存関係の分析結果を追加
        if (dependencyAnalysis) {
          const depAnalysis = JSON.parse(dependencyAnalysis);
          securityReport += '### 依存関係の分析\n\n';
          
          for (const dep of depAnalysis.dependencies) {
            securityReport += `#### ${dep.name}\n`;
            securityReport += `- バージョン変更: ${dep.version_change.from} → ${dep.version_change.to}\n`;
            if (dep.security_findings) {
              securityReport += `- 重要度: ${dep.security_findings.severity}\n`;
              if (dep.security_findings.cves.length > 0) {
                securityReport += `- 関連するCVE: ${dep.security_findings.cves.join(', ')}\n`;
              }
              securityReport += `- 詳細: ${dep.security_findings.description}\n`;
              securityReport += `- 影響を受けるコンポーネント: ${dep.security_findings.affected_components.join(', ')}\n`;
              securityReport += '- 証拠:\n';
              securityReport += `  - リリースノート: ${dep.security_findings.evidence.release_notes}\n`;
              securityReport += `  - 実装の変更: ${dep.security_findings.evidence.implementation_changes}\n`;
            }
            securityReport += '\n推奨される対応:\n';
            for (const action of dep.recommendations.actions) {
              securityReport += `- ${action}\n`;
            }
            securityReport += '\n';
          }

          securityReport += '### 全体的なリスク評価\n';
          securityReport += `- リスクレベル: ${depAnalysis.overall_risk_assessment.risk_level}\n`;
          securityReport += `- 概要: ${depAnalysis.overall_risk_assessment.summary}\n`;
          securityReport += `- 即時対応の必要性: ${depAnalysis.overall_risk_assessment.requires_immediate_action ? 'あり' : 'なし'}\n\n`;
        }

        // 脆弱性スキャン結果を追加
        if (vulnerabilityResults.vulnerabilities) {
          securityReport += '### 脆弱性スキャン結果\n\n';
          
          for (const vuln of vulnerabilityResults.vulnerabilities) {
            if (severityLevels.indexOf(vuln.severity.toLowerCase()) >= severityIndex) {
              hasHighSeverity = true;
            }
            
            securityReport += `#### ${vuln.type}\n`;
            securityReport += `- 重要度: ${vuln.severity}\n`;
            securityReport += `- 説明: ${vuln.description}\n`;
            securityReport += '- 技術的詳細:\n';
            securityReport += `  - 影響を受けるコード: ${vuln.technical_details.affected_code}\n`;
            securityReport += `  - 攻撃ベクトル: ${vuln.technical_details.attack_vectors.join(', ')}\n`;
            securityReport += `  - 影響分析: ${vuln.technical_details.impact_analysis}\n`;
            securityReport += `  - 根本原因: ${vuln.technical_details.root_cause}\n`;
            securityReport += '- 対策:\n';
            securityReport += `  - 推奨される修正: ${vuln.mitigation.recommended_fix}\n`;
            securityReport += `  - セキュリティベストプラクティス: ${vuln.mitigation.security_best_practices.join(', ')}\n\n`;
          }

          if (vulnerabilityResults.analysis_metadata) {
            securityReport += '### 分析メタデータ\n';
            securityReport += `- スキャン範囲: ${vulnerabilityResults.analysis_metadata.scan_coverage.join(', ')}\n`;
            securityReport += `- 信頼度: ${vulnerabilityResults.analysis_metadata.confidence_level}\n`;
            securityReport += `- 制限事項: ${vulnerabilityResults.analysis_metadata.limitations.join(', ')}\n`;
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
        core.setOutput('result', '脆弱性は検出されませんでした');
      } catch (error) {
        console.error('スキャン中にエラーが発生しました:', error);
        core.setFailed(`スキャンに失敗しました: ${error.message}`);
      }
    } else {
      console.log(`現在のイベントタイプ: ${context.eventName} (PRイベントではありません)`);
      core.setOutput('result', 'PRイベント以外ではスキャンは実行されません');
    }
  } catch (error) {
    core.setFailed(`アクションが失敗しました: ${error.message}`);
  }
}

run(); 