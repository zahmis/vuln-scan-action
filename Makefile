.PHONY: all install build test clean release

# バージョン変数
VERSION ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v1.0.0")
NEXT_VERSION ?= $(shell echo $(VERSION) | awk -F. '{$$NF = $$NF + 1;} 1' | sed 's/ /./g')
BRANCH ?= $(shell git rev-parse --abbrev-ref HEAD)

# デフォルトターゲット
all: install build

# 依存関係のインストール
install:
	@echo "📦 依存関係をインストールしています..."
	npm install

# ビルド実行
build:
	@echo "🔨 ビルドを実行しています..."
	npm run build

# テスト実行（将来的な実装のために）
test:
	@echo "🧪 テストを実行しています..."
	npm test

# クリーンアップ
clean:
	@echo "🧹 クリーンアップを実行しています..."
	rm -rf node_modules
	rm -rf dist
	rm -f package-lock.json

# 開発用セットアップ（.envファイルの作成を含む）
dev-setup:
	@echo "🛠️ 開発環境をセットアップしています..."
	@if [ ! -f .env ]; then \
		echo "PERPLEXITY_API_KEY=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" > .env; \
		echo "✅ .envファイルを作成しました"; \
	else \
		echo "⚠️ .envファイルは既に存在します"; \
	fi

# 完全なセットアップ（クリーン→インストール→ビルド）
setup: clean install build dev-setup
	@echo "✨ セットアップが完了しました"

# GitHub Actionsのローカルテスト用
test-action: build
	@echo "🚀 GitHub Actionをローカルでテストしています..."
	act -j scan

# 現在の状態を表示
status:
	@echo "📊 プロジェクトの状態:"
	@echo "Node.jsバージョン: $$(node -v)"
	@echo "NPMバージョン: $$(npm -v)"
	@if [ -f .env ]; then \
		echo "✅ .env: 設定済み"; \
	else \
		echo "❌ .env: 未設定"; \
	fi
	@if [ -d node_modules ]; then \
		echo "✅ 依存関係: インストール済み"; \
	else \
		echo "❌ 依存関係: 未インストール"; \
	fi
	@if [ -d dist ]; then \
		echo "✅ ビルド: 完了"; \
	else \
		echo "❌ ビルド: 未実行"; \
	fi

# package.jsonのバージョン更新
update-version:
	@echo "📝 package.jsonのバージョンを更新しています..."
	@sed -i '' 's/"version": ".*"/"version": "$(subst v,,$(NEXT_VERSION))"/' package.json

# リリースプロセス（ビルド、コミット、タグ付け、プッシュ、リリース作成）
release: build update-version
	@echo "🚀 リリースプロセスを開始します..."
	@echo "現在のバージョン: $(VERSION)"
	@echo "次のバージョン: $(NEXT_VERSION)"
	@read -p "リリースを続行しますか？ [y/N] " answer; \
	if [ "$$answer" != "y" ]; then \
		echo "リリースを中止します"; \
		exit 1; \
	fi
	@echo "🔨 変更をコミットしています..."
	git add .
	git commit -m "Release $(NEXT_VERSION)"
	@echo "🏷️ タグを付けています..."
	git tag -a $(NEXT_VERSION) -m "Release $(NEXT_VERSION)"
	@echo "⬆️ 変更をプッシュしています..."
	git push origin $(BRANCH)
	git push origin $(NEXT_VERSION)
	@echo "📦 GitHubリリースを作成しています..."
	gh release create $(NEXT_VERSION) \
		--title "Release $(NEXT_VERSION)" \
		--notes "## 変更点\n\n- このリリースの変更点を記載してください" \
		./dist/*
	@echo "✨ リリースが完了しました！"

# 次のバージョン番号を表示
next-version:
	@echo "次のバージョン: $(NEXT_VERSION)" 