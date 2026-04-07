# src/scanner/ast.js — AST 解析エンジン

## 概要

`acorn` パーサを使って JavaScript/TypeScript ファイルを抽象構文木（AST）に解析し、危険なパターンを検出するスキャナです。MUAD'DIB の中核となる解析エンジンで、最も多くの脅威タイプを検出します。

## エクスポート

```js
module.exports = { analyzeAST };
```

## `analyzeAST(targetPath, options)` の動作

`shared/analyze-helper.js` の `analyzeWithDeobfuscation()` を呼び出して対象ディレクトリ内の全 JS/TS ファイルを走査します。各ファイルに対して `analyzeFile()` を適用します。

`options.deobfuscate` に難読化解除関数が渡されている場合、解析前にファイル内容をデオブファスケートします。

## `analyzeFile(content, filePath, basePath)` の動作

### AST パース失敗時のフォールバック

`acorn` でのパースが失敗した場合、以下の正規表現フォールバックを適用します：

- `.github/workflows` への読み書き → `workflow_write` (CRITICAL)
- 長いコードが数行しかない場合 → `possible_obfuscation` (MEDIUM)
- `Proxy` + `child_process` + `exec` の組み合わせ → CRITICAL

### 正常 AST 走査

`acorn-walk` の `walk.simple()` を使用して各ノードタイプに対応するハンドラを呼び出します：

| ノードタイプ | ハンドラ | 主な検出内容 |
|---|---|---|
| `VariableDeclarator` | `handleVariableDeclarator` | `require()` の変数代入を追跡 |
| `CallExpression` | `handleCallExpression` | 危険な関数呼び出し（`eval`, `exec`, `spawn` 等）|
| `ImportExpression` | `handleImportExpression` | 動的 `import()` |
| `NewExpression` | `handleNewExpression` | `new Function()`, `new WebSocket()` 等 |
| `Literal` | `handleLiteral` | 不審な文字列リテラル（IP アドレス, Base64 等） |
| `AssignmentExpression` | `handleAssignmentExpression` | プロトタイプ汚染、グローバル上書き |
| `MemberExpression` | `handleMemberExpression` | `process.env`, `process.mainModule` 等のアクセス |
| `WithStatement` | `handleWithStatement` | `with` 文の使用（難読化手法） |

走査完了後、`handlePostWalk(state)` でウォーク中に収集した情報を元に追加の脅威を生成します（例: クレデンシャル読み取り + ネットワーク送信のペア）。

## AST 検出器サブシステム（`src/scanner/ast-detectors/`）

```
ast-detectors/
 ├── index.js                     全ハンドラのエクスポート
 ├── handle-call-expression.js    eval/exec/spawn/require/fetch 等
 ├── handle-variable-declarator.js require 追跡・危険モジュール代入
 ├── handle-import-expression.js  動的 import
 ├── handle-new-expression.js     new Function / new WebSocket 等
 ├── handle-literal.js            不審な文字列リテラル
 ├── handle-assignment-expression.js プロトタイプ汚染
 ├── handle-member-expression.js  process.env / process.mainModule 等
 ├── handle-with-statement.js     with 文
 ├── handle-post-walk.js          ポストウォーク検出
 ├── helpers.js                   共通ユーティリティ
 └── constants.js                 パターン定数
```

## 検出される主な脅威タイプ

| 脅威タイプ | severity | 検出内容 |
|---|---|---|
| `eval_usage` | CRITICAL | `eval()` の呼び出し |
| `dangerous_exec` | HIGH | `exec` / `spawn` / `execSync` 等 |
| `dynamic_require` | HIGH | 変数を引数にした `require()` |
| `network_request` | HIGH | `http.request` / `https.request` / `fetch` |
| `workflow_write` | CRITICAL | `.github/workflows` への書き込み |
| `sensitive_string` | HIGH | `.npmrc` / `.ssh` / `.env` ファイルの参照 |
| `prototype_hook` | HIGH | プロトタイプ上書き |
| `env_access` | MEDIUM | `process.env` アクセス |
| `possible_obfuscation` | MEDIUM | パース不可能な疑わしいコード |

## EXCLUDED_FILES

MUAD'DIB 自身のソースファイルが自己スキャン時に誤検知されないよう、以下のファイルは AST スキャンから除外されます：

```js
const EXCLUDED_FILES = [
  'src/scanner/ast.js',
  'src/scanner/shell.js',
  'src/scanner/package.js',
  'src/response/playbooks.js'
];
```

## 依存関係

```
src/scanner/ast.js
 ├── acorn                           (parse)
 ├── acorn-walk                      (walk.simple)
 ├── src/shared/constants.js         (ACORN_OPTIONS, safeParse)
 ├── src/shared/analyze-helper.js    (analyzeWithDeobfuscation)
 └── src/scanner/ast-detectors/      (各ハンドラ)
```
