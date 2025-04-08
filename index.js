const core = require('@actions/core');
const github = require('@actions/github');
const https = require('node:https');

function getDiffContent(url) {
  return new Promise((resolve, reject) => {
    https.get(url, res => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => resolve(data));
      res.on('error', err => reject(err));
    }).on('error', err => reject(err));
  });
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

    console.log('開始: 脆弱性スキャン');
    console.log(`重要度レベル: ${severityLevel}`);
    console.log(`スキャン対象ディレクトリ: ${scanDirectory}`);
    console.log(`リポジトリ: ${context.repo.owner}/${context.repo.repo}`);
    console.log('GitHub Context:', {
      eventName: context.eventName,
      sha: context.sha,
      ref: context.ref,
      workflow: context.workflow,
      action: context.action,
      actor: context.actor,
      payload: {
        ...context.payload,
        // 大きすぎる可能性のあるフィールドは除外
        repository: '[Repository Object]',
        sender: '[Sender Object]'
      }
    });

    // PRの場合、情報を表示
    if (context.eventName === 'pull_request') {
      console.log('PRイベントを検出しました');
      const pullRequest = context.payload.pull_request;

      console.log('PR情報:', {
        number: pullRequest.number,
        title: pullRequest.title,
        base: pullRequest.base.ref,
        head: pullRequest.head.ref,
        commits: pullRequest.commits,
        additions: pullRequest.additions,
        deletions: pullRequest.deletions,
        changed_files: pullRequest.changed_files
      });

      // 差分の詳細を取得
      try {
        const diff = await getDiffContent(pullRequest.diff_url);
        console.log('PR差分の詳細:');
        console.log(diff);
      } catch (error) {
        console.log('差分の取得に失敗しました:', error.message);
      }
    } else {
      console.log(`現在のイベントタイプ: ${context.eventName} (PRイベントではありません)`);
    }
    
    // ここでは単純な出力のみ（実際のスキャンロジックはここに実装します）
    core.info('これは脆弱性スキャンのデモ実装です');
    core.info('実際のスキャンは今後実装されます');
    
    // サンプル結果の出力
    core.notice('スキャン完了: 脆弱性は見つかりませんでした');
    
    // 成功メッセージをセット
    core.setOutput('result', '脆弱性は検出されませんでした');
  } catch (error) {
    core.setFailed(`アクションが失敗しました: ${error.message}`);
  }
}

run(); 