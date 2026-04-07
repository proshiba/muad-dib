# src/pipeline/outputter.js — Phase 4: 出力

## 概要

スキャンパイプラインの最終フェーズです。スキャン結果を CLI テキスト・JSON・HTML・SARIF などの形式でフォーマット・出力し、Webhook 通知を送信し、終了コードを返します。

## エクスポート

```js
module.exports = { output };
```

## `output(result, options, processed)` の動作

### 1. フォーマット済み出力

`output-formatter.js` の `formatOutput()` を呼び出します。`options` の内容に応じて以下の形式で出力されます：

| オプション | 出力形式 |
|---|---|
| デフォルト（なし） | CLI テキスト（カラー付き） |
| `--json` | JSON を stdout に出力 |
| `--html <file>` | HTML レポートをファイルに保存 |
| `--sarif <file>` | SARIF 形式をファイルに保存 |
| `--explain` | ルール詳細・プレイブックを追加表示 |

### 2. Webhook 送信

`options.webhook` が指定されており、かつ脅威が 1 件以上検出された場合に `webhook.js` の `sendWebhook()` を呼び出します。失敗時は警告を出力してスキャン結果には影響しません。

### 3. 終了コード の計算

`options.failLevel`（デフォルト: `'high'`）に基づいて終了コードを決定します：

| `failLevel` | チェック対象 severity |
|---|---|
| `none` | 常に 0 を返す |
| `critical` | CRITICAL のみ |
| `high` | CRITICAL, HIGH |
| `medium` | CRITICAL, HIGH, MEDIUM |
| `low` | CRITICAL, HIGH, MEDIUM, LOW |

終了コード = min(該当脅威数, 125)

- `0`: 脅威なし（クリーン）
- `>0`: 検出された脅威の件数（max 125）

## 依存関係

```
src/pipeline/outputter.js
 ├── src/output-formatter.js   (formatOutput)
 └── src/webhook.js            (sendWebhook) ← try/catch で任意依存
```
