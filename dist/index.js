/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ 568:
/***/ ((module) => {

module.exports = eval("require")("@actions/core");


/***/ }),

/***/ 192:
/***/ ((module) => {

module.exports = eval("require")("@actions/github");


/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __nccwpck_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		var threw = true;
/******/ 		try {
/******/ 			__webpack_modules__[moduleId](module, module.exports, __nccwpck_require__);
/******/ 			threw = false;
/******/ 		} finally {
/******/ 			if(threw) delete __webpack_module_cache__[moduleId];
/******/ 		}
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat */
/******/ 	
/******/ 	if (typeof __nccwpck_require__ !== 'undefined') __nccwpck_require__.ab = __dirname + "/";
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
const core = __nccwpck_require__(568);
const github = __nccwpck_require__(192);

async function run() {
  try {
    // 入力パラメータを取得
    const severityLevel = core.getInput('severity-level');
    const scanDirectory = core.getInput('scan-directory');

    // 現在のコンテキスト情報を取得
    const context = github.context;
    
    console.log('開始: 脆弱性スキャン');
    console.log('重要度レベル: ' + severityLevel);
    console.log('スキャン対象ディレクトリ: ' + scanDirectory);
    console.log('リポジトリ: ' + context.repo.owner + '/' + context.repo.repo);
    
    // ここでは単純な出力のみ（実際のスキャンロジックはここに実装します）
    core.info('これは脆弱性スキャンのデモ実装です');
    core.info('実際のスキャンは今後実装されます');
    
    // サンプル結果の出力
    core.notice('スキャン完了: 脆弱性は見つかりませんでした');
    
    // 成功メッセージをセット
    core.setOutput('result', '脆弱性は検出されませんでした');
  } catch (error) {
    core.setFailed('アクションが失敗しました: ' + error.message);
  }
}

run(); 
module.exports = __webpack_exports__;
/******/ })()
;