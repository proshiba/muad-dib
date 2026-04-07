# src/scanner/module-graph/ — クロスファイルモジュールグラフ解析

## 概要

複数ファイルにまたがるデータフローを検出するサブシステムです。パッケージ内のモジュール間の `require`/`import` 関係を有向グラフとして構築し、汚染された export が別ファイルの sink に流れるパターンを検出します。

## ファイル構成

```
src/scanner/module-graph/
 ├── index.js                  全シンボルのエクスポート
 ├── build-graph.js            モジュールグラフの構築
 ├── annotate-tainted.js       taint 付き export の特定
 ├── annotate-sinks.js         sink 付き export の特定
 ├── detect-cross-file.js      クロスファイルデータフロー検出
 ├── detect-callback-flows.js  コールバック経由フロー検出
 ├── detect-event-flows.js     EventEmitter 経由フロー検出
 ├── parse-utils.js            ファイルパース・パス解決ユーティリティ
 └── constants.js              上限定数
```

## 主要な上限定数（`constants.js`）

| 定数 | 値 | 説明 |
|---|---|---|
| `MAX_GRAPH_NODES` | 100 | グラフノード（ファイル）の最大数 |
| `MAX_GRAPH_EDGES` | 500 | グラフエッジ（依存）の最大数 |
| `MAX_FLOWS` | 50 | 検出するフローの最大数 |
| `MAX_TAINT_DEPTH` | 5 | taint 追跡の最大深さ |

## `buildModuleGraph(targetPath)` — グラフ構築

対象ディレクトリ内の全 JS ファイルを走査し、`require()` / `import` の依存関係を有向グラフとして構築します。

```js
// グラフのデータ構造
{
  'lib/helper.js': {
    imports: ['./util.js'],
    exports: ['readCredential']
  },
  'index.js': {
    imports: ['./lib/helper.js'],
    exports: []
  }
}
```

ノード数が `MAX_GRAPH_NODES` を超えた場合は空オブジェクトを返します（executor.js で警告を出力）。

## `annotateTaintedExports(graph, targetPath)` — taint 付き export の特定

グラフ内の各ファイルを解析し、ファイル読み取り・環境変数アクセス・コマンド実行などの「汚染されたソース」から得た値を export しているファイルを特定します。

## `annotateSinkExports(graph, targetPath)` — sink 付き export の特定

ネットワーク送信・コマンド実行などの「シンク」を内部で呼び出す関数を export しているファイルを特定します。

## `detectCrossFileFlows(graph, tainted, sinks, targetPath)` — クロスファイルフロー検出

taint 付き export が別ファイルでシンクに渡されるパターンを検出します。

```
credential_source (lib/config.js) → network_send (lib/reporter.js)
  ↑ この流れを cross_file_dataflow として CRITICAL で報告
```

## `detectCallbackCrossFileFlows(graph, tainted, sinks, targetPath)` — コールバックフロー

コールバック関数として taint データを渡すパターンを検出します：

```js
// lib/config.js が認証トークンを読み取り
// index.js がそのコールバックをネットワーク関数に渡す
httpClient.post(url, credentialReader)  // コールバック経由フロー
```

## `detectEventEmitterFlows(graph, tainted, sinks, targetPath)` — EventEmitter フロー

EventEmitter を介したクロスモジュールフローを検出します：

```js
emitter.on('data', credentialHandler);  // taint をイベント経由で sink に流す
```

## 検出される脅威タイプ

| 脅威タイプ | severity | 説明 |
|---|---|---|
| `cross_file_dataflow` | CRITICAL | taint 付きデータがファイルをまたいでシンクへ流れた |

## 実行タイムアウト

`executor.js` から呼び出す際は 5 秒のタイムアウトが設定されています。タイムアウト発生時はグレースフルフォールバックし、クロスファイルフロー検出の結果は空になります（他スキャナには影響なし）。

## 依存関係

```
src/scanner/module-graph/
 ├── acorn                 (parse — parse-utils.js 経由)
 ├── acorn-walk            (walk.simple — parse-utils.js 経由)
 └── (node 標準モジュールのみ)
```
