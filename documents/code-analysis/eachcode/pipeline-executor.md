# src/pipeline/executor.js — Phase 2: スキャン実行

## 概要

スキャンパイプラインの第 2 フェーズです。モジュールグラフの構築と 13 個のスキャナを並列実行して、すべての脅威を収集します。

## エクスポート

```js
module.exports = { execute, matchPythonIOCs, checkPyPITyposquatting };
```

## `execute(targetPath, options, pythonDeps, warnings)` の動作

### ステップ 1: デオブファスケーション関数の準備

`options.noDeobfuscate` が未設定の場合、`scanner/deobfuscate.js` の `deobfuscate` 関数を AST/データフロースキャナに渡します。

### ステップ 2: モジュールグラフ構築（クロスファイル解析）

`options.noModuleGraph` が未設定の場合、5 秒のタイムアウト付きでモジュールグラフを構築します：

```
buildModuleGraph(targetPath)
  → annotateTaintedExports(graph)   taint 付き export を特定
  → annotateSinkExports(graph)      sink 付き export を特定
  → detectCrossFileFlows()          ファイルをまたいだデータフロー検出
  → detectCallbackCrossFileFlows()  コールバック経由のクロスファイルフロー
  → detectEventEmitterFlows()       EventEmitter 経由のクロスファイルフロー
```

100 ファイル超のパッケージはグラフ構築をスキップし、警告を出力します。タイムアウト発生時はグレースフルフォールバック（部分的な結果なし）。

### ステップ 3: 13 スキャナの並列実行

`Promise.allSettled` を使用して全スキャナを並列実行します。1 つのスキャナがクラッシュしても他のスキャナの結果は保持されます。

重いスキャナ（AST・データフロー・エントロピー）には 45 秒の個別タイムアウトが設定されています。

| スキャナ名 | 関数 | 説明 |
|---|---|---|
| `scanPackageJson` | `scanner/package.js` | `package.json` のライフサイクルスクリプト解析 |
| `scanShellScripts` | `scanner/shell.js` | シェルスクリプトの正規表現パターン検出 |
| `analyzeAST` | `scanner/ast.js` | AST 解析（acorn）— タイムアウト 45 秒 |
| `detectObfuscation` | `scanner/obfuscation.js` | 難読化コードの検出 |
| `scanDependencies` | `scanner/dependencies.js` | 依存関係の IOC 照合・URL 検出 |
| `scanHashes` | `scanner/hash.js` | SHA256 ハッシュ照合 |
| `analyzeDataFlow` | `scanner/dataflow.js` | データフロー解析 — タイムアウト 45 秒 |
| `scanTyposquatting` | `scanner/typosquat.js` | npm タイポスクワット検出 |
| `scanGitHubActions` | `scanner/github-actions.js` | GitHub Actions YAML 解析 |
| `matchPythonIOCs` | （内部関数） | PyPI IOC DB 照合 |
| `checkPyPITyposquatting` | （内部関数） | PyPI タイポスクワット検出 |
| `scanEntropy` | `scanner/entropy.js` | Shannon エントロピー解析 — タイムアウト 45 秒 |
| `scanAIConfig` | `scanner/ai-config.js` | AI 設定ファイルへのプロンプトインジェクション検出 |

### ステップ 4: ファイル数オーバーフロー処理

対象ファイルが 500 件を超えた場合（`wasFilesCapped()` が `true`）、オーバーフローしたファイルに対して以下のパターンのみ正規表現でクイックスキャンします：

- `require('child_process')` / `require('node:child_process')`
- `exec` / `execSync` / `spawn` / `spawnSync` の呼び出し
- `process.mainModule`
- `Module._load`

### ステップ 5: Paranoid モード（`--paranoid`）

`scanParanoid(targetPath)` を呼び出してより厳格なパターン検出を追加します。

### ステップ 6: テンポラル解析（`--temporal`系オプション）

過去バージョンとの diff 分析・公開日異常・メンテナー変更の検出を行います。

## `matchPythonIOCs(deps, targetPath)` — PyPI IOC 照合

Phase 1 で検出した Python 依存関係をロード済みの IOC データベースと照合します。

照合は以下の順序で行われます：

1. **ワイルドカードマップ** (`pypiWildcardPackages`): 全バージョンが悪意あるパッケージ
2. **バージョン別マップ** (`pypiPackagesMap`): 特定バージョンのみ悪意あるパッケージ
3. **フォールバック**: 線形検索（Map が利用不能な場合のみ）

## `checkPyPITyposquatting(deps, targetPath)` — PyPI タイポスクワット

`typosquat.js` の `findPyPITyposquatMatch()` を呼び出して Levenshtein 距離でポピュラー PyPI パッケージに酷似した依存関係名を検出します。

## 依存関係

```
src/pipeline/executor.js
 ├── src/scanner/package.js
 ├── src/scanner/shell.js
 ├── src/scanner/ast.js
 ├── src/scanner/obfuscation.js
 ├── src/scanner/dependencies.js
 ├── src/scanner/hash.js
 ├── src/scanner/dataflow.js
 ├── src/scanner/typosquat.js
 ├── src/scanner/github-actions.js
 ├── src/scanner/entropy.js
 ├── src/scanner/ai-config.js
 ├── src/scanner/deobfuscate.js
 ├── src/scanner/module-graph/
 ├── src/scanner/python.js
 ├── src/scanner/paranoid.js
 ├── src/ioc/updater.js
 ├── src/temporal-runner.js
 └── src/utils.js
```
