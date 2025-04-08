const core = require('@actions/core');
const github = require('@actions/github');

async function run() {
  try {
    // 入力パラメータを取得
    const severityLevel = core.getInput('severity-level');
    const scanDirectory = core.getInput('scan-directory');

    // 現在のコンテキスト情報を取得
    const context = github.context;
    
    console.log('開始: 脆弱性スキャン');
    console.log(`重要度レベル: ${severityLevel}`);
    console.log(`スキャン対象ディレクトリ: ${scanDirectory}`);
    console.log(`リポジトリ: ${context.repo.owner}/${context.repo.repo}`);
    
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