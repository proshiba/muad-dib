# src/pipeline/processor.js — Phase 3: 脅威処理

## 概要

スキャンパイプラインの第 3 フェーズです。全スキャナが収集した生の脅威配列を受け取り、重複排除・Compound ルール評価・FP 削減・Intent 解析・ルールエンリッチ・リスクスコア計算を行います。

## エクスポート

```js
module.exports = { process };
```

## `process(threats, targetPath, options, pythonDeps, warnings, scannerErrors)` の処理フロー

### 1. Auto-Sandbox トリガー判定

`options.autoSandbox` が設定されている場合、CRITICAL/HIGH 脅威の予備スコアを計算し、スコアが 20 以上であれば Docker サンドボックスを起動します。Docker が利用不能な場合はサイレントにスキップします。

### 2. サンドボックス結果の統合

`options.sandboxResult` にサンドボックスの findings がある場合、`sandbox_*` タイプの脅威として `threats` 配列に追加します。

### 3. 重複排除

`file + type + message` の組み合わせをキーとして同一脅威をまとめます。同一キーが複数ある場合は `count` フィールドをインクリメントします。

### 4. Compound ルール評価

#### Compound A: `detached_credential_exfil`

同一ファイル内に `detached_process` と `suspicious_dataflow` が共存する場合に合成 CRITICAL 脅威を追加します。dist/build/min ファイルはバンドラーの集約による偶発的共存のためスキップします。

#### Compound B: `lifecycle_file_exec`

ライフサイクルスクリプト（`preinstall` 等）が `node xxx.js` で呼び出す JS ファイルに HIGH/CRITICAL 脅威が検出されている場合、インストール時マルウェアとして CRITICAL を追加します。

### 5. Reachability 解析

`scanner/reachability.js` でパッケージのエントリポイントから到達可能なファイルのセットを計算します。到達不可能なファイルの脅威は後続の FP 削減や Intent 評価で重みを下げられます。

### 6. FP 削減（`applyFPReductions`）

`scoring.js` の `applyFPReductions()` を呼び出し、正規フレームワークが大量に生成する特定脅威タイプのノイズを抑制します。

### 7. Compound ブースト（`applyCompoundBoosts`）

FP 削減後、悪意の高い組み合わせが残っている場合に合成 CRITICAL 脅威を注入します。FP 削減で個別に抑制された後でも強いシグナルを回復するためです。

### 8. Intent グラフ解析（`buildIntentPairs`）

`intent-graph.js` の `buildIntentPairs()` を呼び出し、同一ファイル内のクレデンシャル読み取りソースとネットワーク送信シンクのペアを検出します。SDK パターン（AWS_* → amazonaws.com 等）は除外します。

到達不可能ファイルの Intent 脅威は `LOW` にダウングレードされます。

### 9. ルールエンリッチメント

各脅威に対して `rules/index.js` から `rule_id`・`rule_name`・`confidence`・`references`・`mitre` を付加し、`playbooks.js` から `playbook`（対応手順）を付加します。信頼度係数（high=1.0, medium=0.85, low=0.6）を乗じてポイントを計算します。

### 10. リスクスコア計算

`calculateRiskScore(deduped, intentResult)` でリスクスコアを算出します：

```
riskScore = min(100, max(ファイルスコア) + パッケージレベルスコア)
```

詳細は [scoring.md](./scoring.md) を参照。

## 戻り値

```js
{
  result: ScanResult,           // 最終スキャン結果オブジェクト
  deduped: Threat[],            // 重複排除済み脅威
  enrichedThreats: Threat[],    // エンリッチ済み脅威
  sandboxData: object|null,
  pythonInfo: object|null,
  breakdown: BreakdownItem[],   // スコアブレークダウン
  mostSuspiciousFile: string|null,
  maxFileScore: number,
  packageScore: number,
  globalRiskScore: number
}
```

## 依存関係

```
src/pipeline/processor.js
 ├── src/rules/index.js               (getRule)
 ├── src/response/playbooks.js        (getPlaybook)
 ├── src/scanner/reachability.js      (computeReachableFiles)
 ├── src/scoring.js                   (applyFPReductions, applyCompoundBoosts, calculateRiskScore, getSeverityWeights)
 ├── src/intent-graph.js              (buildIntentPairs)
 ├── src/sandbox/index.js             (isDockerAvailable, buildSandboxImage, runSandbox) ← 動的 require
 └── src/utils.js                     (debugLog)
```
