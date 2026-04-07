# src/pipeline/initializer.js — Phase 1: 初期化

## 概要

スキャンパイプラインの第 1 フェーズを担当するモジュールです。スキャン本体を実行する前に必要なすべての前処理（パス検証・IOC 読み込み・設定適用・Python 検出）を行います。

## エクスポート

```js
module.exports = { initialize };
```

## `initialize(targetPath, options)` の動作

```
initialize(targetPath, options)
 │
 ├─ 1. targetPath の存在・ディレクトリ確認
 │       存在しない or ディレクトリでない場合は Error をスロー
 │
 ├─ 2. ensureIOCs()
 │       IOC データベースが未ダウンロードの場合に自動取得（初回のみ）
 │       失敗してもスキャン自体は継続（graceful degradation）
 │
 ├─ 3. checkIOCStaleness(30)
 │       IOC DB が 30 日以上古い場合に警告文字列を返す
 │
 ├─ 4. options.exclude の適用
 │       --exclude で指定されたディレクトリをファイル列挙から除外
 │       utils.js の setExtraExcludes() を呼び出す
 │
 ├─ 5. resolveConfig(targetPath, options.configPath)
 │       .muaddibrc.json または --config で指定されたファイルを読み込む
 │       エラーがあれば即座に Error をスロー
 │       有効な設定があれば applyConfigOverrides() で scoring.js に反映
 │
 └─ 6. detectPythonProject(targetPath)
         requirements.txt / setup.py / pyproject.toml を解析して
         Python 依存関係リストを構築（同期・高速）
```

### 戻り値

```js
{
  pythonDeps: Array<{name: string, version: string, file: string}>,
  configApplied: boolean,
  configResult: { config: object|null, errors: string[], warnings: string[] },
  warnings: string[]
}
```

## 依存関係

```
src/pipeline/initializer.js
 ├── src/utils.js                  (setExtraExcludes)
 ├── src/scanner/python.js         (detectPythonProject)
 ├── src/ioc/bootstrap.js          (ensureIOCs)
 ├── src/ioc/updater.js            (checkIOCStaleness)
 ├── src/config.js                 (resolveConfig)
 ├── src/scoring.js                (applyConfigOverrides)
 └── src/shared/constants.js       (setMaxFileSize)
```

## 設定ファイル（`.muaddibrc.json`）

`resolveConfig()` はプロジェクトルートの `.muaddibrc.json` を探します。設定できる主なフィールド：

| フィールド | 型 | 説明 |
|---|---|---|
| `severityWeights` | object | CRITICAL/HIGH/MEDIUM/LOW のスコアウェイトを上書き |
| `riskThresholds` | object | リスクレベル判定しきい値を上書き |
| `maxFileSize` | number | スキャン対象ファイルの最大サイズ（バイト） |
| `exclude` | string[] | 除外するディレクトリ・ファイルのパターン |
