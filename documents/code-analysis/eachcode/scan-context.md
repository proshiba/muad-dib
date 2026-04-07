# src/scan-context.js — スキャンコンテキスト管理

## 概要

スキャン単位のミュータブル（可変）な状態を管理し、スキャン終了後にすべての状態をリセットするための集約モジュールです。MUAD'DIB をライブラリとして複数回呼び出す際のスキャン間の状態リークを防ぎます。

## エクスポート

```js
module.exports = { resetAll };
```

## なぜ必要か

MUAD'DIB の複数モジュールはスキャン設定・キャッシュなどのミュータブルな状態を保持しています。例えば：

- `utils.js`: ファイルリストキャッシュ、コンテンツキャッシュ、除外設定
- `scoring.js`: severity ウェイト、リスクしきい値（`.muaddibrc.json` 上書き）
- `shared/constants.js`: 最大ファイルサイズ（設定上書き）、AST パースキャッシュ

これらを各スキャン後にリセットしないと、前のスキャンの設定が次のスキャンに影響します。

## `resetAll()` の動作

```js
function resetAll() {
  setExtraExcludes([]);   // utils.js: 除外設定をクリア
  clearFileListCache();   // utils.js: ファイルリストキャッシュをクリア
  resetConfigOverrides(); // scoring.js: スコアリング設定を初期値に戻す
  resetMaxFileSize();     // shared/constants.js: ファイルサイズ上限を初期値に戻す
  clearASTCache();        // shared/constants.js: AST パースキャッシュをクリア
}
```

## 呼び出しタイミング

`src/index.js` の `run()` 関数で `finally` ブロックにより呼び出されます：

```js
async function run(targetPath, options = {}) {
  try {
    // ... パイプライン実行 ...
  } finally {
    resetAll();  // 例外発生時も必ず実行される
  }
}
```

これにより、スキャンが正常終了した場合も例外で中断した場合も、確実に状態がリセットされます。

## 管理される状態一覧

| 状態 | 所有モジュール | リセット関数 |
|---|---|---|
| ファイルリストキャッシュ | `utils.js` | `clearFileListCache()` |
| 追加除外ディレクトリ | `utils.js` | `setExtraExcludes([])` |
| severity ウェイト | `scoring.js` | `resetConfigOverrides()` |
| リスクしきい値 | `scoring.js` | `resetConfigOverrides()` |
| 最大ファイルサイズ | `shared/constants.js` | `resetMaxFileSize()` |
| AST パースキャッシュ | `shared/constants.js` | `clearASTCache()` |

## 依存関係

```
src/scan-context.js
 ├── src/utils.js              (setExtraExcludes, clearFileListCache)
 ├── src/scoring.js            (resetConfigOverrides)
 └── src/shared/constants.js   (resetMaxFileSize, clearASTCache)
```
