# src/intent-graph.js — インテントグラフ解析

## 概要

同一ファイル内にクレデンシャルの「ソース」と「シンク」の両方が存在するかを検出するモジュールです。スキャナが個別に検出した脅威タイプを組み合わせることで、単独では見逃しやすい「認証情報窃取 → 外部送信」の意図を推定します。

## 設計原則

1. **同一ファイル内のみ**: クロスファイルのペアリングは FP が多いため、ファイル内に限定（クロスファイルは `module-graph/` が担当）
2. **検出済み脅威のみ参照**: 独自の content スキャンは行わず、スキャナが生成した脅威タイプのみを参照
3. **SDK パターン除外**: 正規 SDK の env var → 対応ドメイン送信は除外（例: `AWS_*` → `amazonaws.com`）
4. **重複スコアなし**: `suspicious_dataflow`（`dataflow.js` の Compound）は除外して二重カウントを防止

## ソースタイプ分類（`SOURCE_TYPES`）

以下の脅威タイプがソースとして認識されます：

| 脅威タイプ | ソース分類 |
|---|---|
| `sensitive_string` | `credential_read` |
| `env_harvesting_dynamic` | `credential_read` |
| `credential_regex_harvest` | `credential_read` |
| `llm_api_key_harvest` | `credential_read` |
| `credential_cli_steal` | `credential_read` |
| `env_access`（センシティブな env var のみ） | `credential_read` |

`env_access` は参照している環境変数名が `TOKEN`, `KEY`, `SECRET`, `PASSWORD`, `CREDENTIAL`, `API_KEY`, `AUTH` を含む場合のみソースとして扱います。

## シンクタイプ分類（`SINK_TYPES`）

以下の脅威タイプがシンクとして認識されます：

| 脅威タイプ | シンク分類 |
|---|---|
| `network_request` | `network_send` |
| `eval_usage` | `code_execution` |
| `dangerous_exec` | `code_execution` |
| `detached_process` | `code_execution` |
| `dns_lookup` | `network_send` |
| `websocket_send` | `network_send` |

## SDK パターン除外（`SDK_ENV_DOMAIN_MAP`）

以下の組み合わせは正規 SDK 使用として除外されます：

| env var パターン | 対応ドメイン |
|---|---|
| `AWS_*` | `amazonaws.com`, `aws.amazon.com` |
| `AZURE_*` | `azure.com`, `microsoft.com` |
| `GOOGLE_*`, `GCP_*` | `googleapis.com`, `google.com` |
| `STRIPE_*` | `stripe.com` |
| `GITHUB_*` | `github.com`, `githubusercontent.com` |
| その他 13 パターン | 各対応ドメイン |

## `buildIntentPairs(threats, targetPath)` の動作

1. 脅威をファイルごとにグループ化
2. 各ファイルでソースとシンクを特定
3. ソース・シンクが共存するファイルで Intent ペアを生成
4. SDK パターンの除外
5. Intent 脅威（`credential_exfil_intent`）を生成

### 戻り値

```js
{
  pairs: IntentPair[],        // source-sink ペアの一覧
  intentThreats: Threat[],    // 生成された脅威オブジェクト
  intentBonus: number         // globalRiskScore への加算ボーナス
}
```

## 検出される脅威タイプ

| 脅威タイプ | severity | 説明 |
|---|---|---|
| `credential_exfil_intent` | CRITICAL | 同一ファイル内にクレデンシャル読み取りと外部送信が共存 |

## 依存関係

```
src/intent-graph.js
 └── (node 標準モジュールのみ)
```
