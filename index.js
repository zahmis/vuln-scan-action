const core = require('@actions/core');
const github = require('@actions/github');

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

    // PRの場合、差分を取得
    if (context.eventName === 'pull_request') {
      console.log('PRイベントを検出しました');
      const { data: pullRequest } = await octokit.rest.pulls.get({
        owner: context.repo.owner,
        repo: context.repo.repo,
        pull_number: context.payload.pull_request.number
      });

      console.log('PR情報:', {
        number: pullRequest.number,
        title: pullRequest.title,
        base: pullRequest.base.ref,
        head: pullRequest.head.ref
      });

      // 差分を取得
      const { data: files } = await octokit.rest.pulls.listFiles({
        owner: context.repo.owner,
        repo: context.repo.repo,
        pull_number: context.payload.pull_request.number
      });

      console.log('変更されたファイル:');
      for (const file of files) {
        console.log(`- ${file.filename} (${file.status}, 変更: +${file.additions}/-${file.deletions})`);
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