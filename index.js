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
    const response = await axios.post(PERPLEXITY_API_ENDPOINT, {
      model: "sonar-pro",
      messages: [
        {
          role: "system",
          content: "依存関係の変更を分析し、セキュリティ上の問題がないか確認してください。結果はJSON形式で返してください。"
        },
        {
          role: "user",
          content: `以下のPR差分から依存関係の変更を分析してください:\n\n${diff}`
        }
      ]
    }, {
      headers: {
        'Authorization': `Bearer ${process.env.PERPLEXITY_API_KEY}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });
    return response.data.choices[0].message.content;
  } catch (error) {
    throw new Error(`依存関係の分析に失敗しました: ${error.message}`);
  }
}

async function analyzeVulnerabilities(diff, severityLevel) {
  try {
    const response = await axios.post(PERPLEXITY_API_ENDPOINT, {
      model: "sonar-pro",
      messages: [
        {
          role: "system",
          content: `コードの脆弱性を分析し、${severityLevel}以上の重要度の問題を検出してください。結果はJSON形式で返してください。`
        },
        {
          role: "user",
          content: `以下のコード差分を分析してください:\n\n${diff}`
        }
      ]
    }, {
      headers: {
        'Authorization': `Bearer ${process.env.PERPLEXITY_API_KEY}`,
        'Content-Type': 'application/json',
        'Accept': 'application/json'
      }
    });

    const analysisResult = JSON.parse(response.data.choices[0].message.content);
    return {
      vulnerabilities: analysisResult.vulnerabilities || []
    };
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
    const perplexityApiKey = core.getInput('perplexity-api-key');

    // 環境変数にAPIキーを設定
    process.env.PERPLEXITY_API_KEY = perplexityApiKey;

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
        if (vulnerabilityResults.vulnerabilities.length > 0) {
          const vulnerabilitiesByLevel = vulnerabilityResults.vulnerabilities.reduce((acc, vuln) => {
            acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
            return acc;
          }, {});

          // 結果の詳細をコメントとして出力
          core.notice(`脆弱性スキャン結果:
            - 重大: ${vulnerabilitiesByLevel.critical || 0}
            - 高: ${vulnerabilitiesByLevel.high || 0}
            - 中: ${vulnerabilitiesByLevel.medium || 0}
            - 低: ${vulnerabilitiesByLevel.low || 0}
          `);

          // 設定された重要度レベル以上の脆弱性が見つかった場合はエラーを出力
          const severityLevels = ['low', 'medium', 'high', 'critical'];
          const severityIndex = severityLevels.indexOf(severityLevel.toLowerCase());
          const hasHighSeverity = vulnerabilityResults.vulnerabilities.some(
            vuln => severityLevels.indexOf(vuln.severity.toLowerCase()) >= severityIndex
          );

          if (hasHighSeverity) {
            core.setFailed(`設定された重要度レベル(${severityLevel})以上の脆弱性が検出されました`);
            return;
          }
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