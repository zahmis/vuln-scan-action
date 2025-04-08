# 脆弱性スキャンアクション

このGitHub Actionは、リポジトリに対して簡単な脆弱性スキャンを実行します。

## 使い方

ワークフローの例:

```yaml
name: セキュリティスキャン

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: 脆弱性スキャンを実行
        uses: your-username/vuln-scan-action@v1
        with:
          severity-level: 'high'  # オプション: high, medium, low (デフォルト: medium)
          scan-directory: '.'     # オプション: スキャンするディレクトリ (デフォルト: .)
```

## 入力パラメータ

| パラメータ | 必須 | デフォルト値 | 説明 |
|------------|------|--------------|------|
| `severity-level` | いいえ | `medium` | 検出する脆弱性の最小重要度レベル (`low`, `medium`, `high`) |
| `scan-directory` | いいえ | `.` | スキャン対象のディレクトリ |

## 出力

| 出力 | 説明 |
|------|------|
| `result` | スキャン結果の概要 |

## ライセンス

MIT