# src/index.js — ライブラリエントリポイント

## 概要

`src/index.js` は MUAD'DIB のライブラリとしてのエントリポイントです。`package.json` の `"main"` フィールドに指定されており、`require('muaddib-scanner')` でインポートした際に最初に読み込まれるファイルです。

CLI からは `bin/muaddib.js` が `src/index.js` の `run()` を呼び出します。

## エクスポート

```js
module.exports = { run, isPackageLevelThreat, computeGroupScore };
```

| シンボル | 種別 | 説明 |
|---|---|---|
| `run` | 非同期関数 | スキャンパイプライン全体を実行するメイン関数 |
| `isPackageLevelThreat` | 関数 | 脅威タイプがパッケージレベルか否かを判定（`scoring.js` から再エクスポート） |
| `computeGroupScore` | 関数 | 脅威グループのスコアを計算（`scoring.js` から再エクスポート） |

## `run(targetPath, options)` の動作

```
run(targetPath, options)
 │
 ├─ Phase 1: initialize(targetPath, options)
 │       パス検証・IOC DB 読み込み・設定適用・Python 依存関係検出
 │       → {pythonDeps, configApplied, configResult, warnings}
 │
 ├─ Phase 2: execute(targetPath, options, pythonDeps, warnings)
 │       13 スキャナを並列実行してすべての脅威を収集
 │       → {threats, scannerErrors}
 │
 ├─ Phase 3: processThreats(threats, targetPath, options, ...)
 │       重複排除・Compound評価・FP削減・Intent解析・スコア算出
 │       → {result, deduped, enrichedThreats, ...}
 │
 └─ Phase 4: output(result, options, processed)
         CLI/JSON/HTML/SARIF 出力、Webhook 送信、終了コード返却
         → exitCode (number)
```

### `_capture` モード

`options._capture = true` の場合、Phase 4 をスキップし、`result` オブジェクトを直接返します。これは `src/diff.js` （スナップショット比較）から利用されます。

### 状態リセット

`finally` ブロックで `scan-context.js` の `resetAll()` を呼び出し、スキャンをまたいだ状態リークを防止します。これはライブラリとして複数回呼ばれる場合（例: CI で複数パッケージを連続スキャン）に重要です。

## 依存関係

```
src/index.js
 ├── src/scoring.js            (isPackageLevelThreat, computeGroupScore)
 ├── src/scan-context.js       (resetAll)
 ├── src/pipeline/initializer.js  (initialize)
 ├── src/pipeline/executor.js     (execute)
 ├── src/pipeline/processor.js    (process)
 └── src/pipeline/outputter.js    (output)
```

## result オブジェクトの構造

`run()` が返す（または `output()` に渡す）`result` オブジェクトの主要フィールド：

```js
{
  target: string,           // スキャン対象パス
  timestamp: string,        // ISO 8601 タイムスタンプ
  threats: EnrichedThreat[], // エンリッチ済み脅威の配列
  python: PythonInfo|null,  // Python プロジェクト情報
  summary: {
    total: number,
    critical: number,
    high: number,
    medium: number,
    low: number,
    riskScore: number,       // 0–100
    riskLevel: string,       // 'SAFE'|'LOW'|'MEDIUM'|'HIGH'|'CRITICAL'
    globalRiskScore: number,
    maxFileScore: number,
    packageScore: number,
    mostSuspiciousFile: string|null,
    fileScores: object,
    breakdown: BreakdownItem[]
  },
  sandbox: SandboxData|null,
  warnings: string[]|undefined,
  scannerErrors: ScannerError[]|undefined
}
```
