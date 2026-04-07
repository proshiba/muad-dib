# src/scanner/dataflow.js — データフロー解析

## 概要

ファイル内のデータフロー（情報の読み取りから送信までの流れ）を追跡して、クレデンシャル窃取やテレメトリ収集などの不審な動作を検出するスキャナです。AST 解析と連携してより精度の高い検出を実現します。

## エクスポート

```js
module.exports = { analyzeDataFlow };
```

## `analyzeDataFlow(targetPath, options)` の動作

`shared/analyze-helper.js` の `analyzeWithDeobfuscation()` を通じて各 JS ファイルに対してデータフロー解析を実行します。

解析は以下の 2 段階で行われます：

### ステップ 1: タントマップ構築（`buildTaintMap`）

AST の pre-pass で `require()` の代入を追跡し、どの変数名がどのモジュールに対応するかをマッピングします。

```js
// 例: const os = require('os') → taintMap: { 'os' → { source: 'os' } }
const os = require('os');
os.homedir();  // → fingerprint_read として検出
```

#### ソースモジュール分類

| モジュール | メソッド | 分類 |
|---|---|---|
| `os` | `homedir`, `networkInterfaces`, `userInfo` | `fingerprint_read` |
| `os` | `hostname`, `platform`, `arch`, `cpus` 等 | `telemetry_read` |
| `fs` | `readFileSync`, `readFile`, `readdirSync` | `credential_read` |
| `child_process` | `exec`, `execSync`, `spawn`, `spawnSync` | `command_output` |

#### シンクモジュール分類

| モジュール | メソッド | 分類 |
|---|---|---|
| `http`/`https` | `request`, `get` | `network_send` |
| `net`/`tls` | `connect`, `createConnection` | `network_send` |
| `dns` | `resolve`, `lookup` 等 | `network_send` |
| `fs` | `writeFileSync`, `writeFile` | `file_tamper` |
| `child_process` | `exec`, `spawn` | `exec_sink` |
| `ws`, `mqtt`, `socket.io` 等 | `send`, `emit`, `publish` | `network_send` |

### ステップ 2: シンク解析

タントマップを参照しながら AST 全体を走査し、汚染された変数がシンクメソッドの引数に流れていないかを検出します。

### exec 結果の捕捉検出

コマンド実行結果（`exec`, `execSync` 等）を変数に代入し、その変数をネットワーク送信に使用するパターンを「コマンド実行結果の外部送信」として検出します。

## 検出される主な脅威タイプ

| 脅威タイプ | severity | 検出内容 |
|---|---|---|
| `suspicious_dataflow` | MEDIUM | ソース → シンク のデータフローが検出された |
| `credential_exfil` | CRITICAL | クレデンシャル読み取り → ネットワーク送信 |
| `telemetry_exfil` | HIGH | システム情報 → ネットワーク送信 |
| `exec_result_exfil` | CRITICAL | コマンド実行結果 → ネットワーク送信 |

## Intent グラフとの違い

| 解析 | 対象 | 方法 |
|---|---|---|
| `dataflow.js` | 同一ファイル内のフロー | タントトラッキング（変数追跡） |
| `intent-graph.js` | 同一ファイル内の脅威ペア | 検出済み脅威タイプの組み合わせ分析 |
| `module-graph/` | クロスファイルのフロー | モジュール export/import の解析 |

## 依存関係

```
src/scanner/dataflow.js
 ├── acorn                        (parse)
 ├── acorn-walk                   (walk.simple)
 ├── src/utils.js                 (getCallName)
 ├── src/shared/constants.js      (ACORN_OPTIONS, safeParse)
 └── src/shared/analyze-helper.js (analyzeWithDeobfuscation)
```
