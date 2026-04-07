# src/ioc/ — IOC データベース管理

## 概要

既知の悪意ある npm/PyPI パッケージ・ファイルハッシュ・マーカー文字列などの IOC（Indicators of Compromise）データベースを管理するサブシステムです。

## ファイル構成

```
src/ioc/
 ├── bootstrap.js      初回自動ダウンロード（ensureIOCs）
 ├── updater.js        IOC の更新・読み込み・インデックス構築
 ├── scraper.js        外部ソースからの IOC 取得
 ├── yaml-loader.js    ビルトイン YAML IOC の読み込み
 └── data/
     ├── iocs-compact.json    コンパクト版 IOC (~5MB、git 管理)
     ├── iocs.json            フル版 IOC (112MB、.gitignore)
     ├── builtin.yaml         ビルトイン IOC（高確信度）
     ├── packages.yaml        既知悪意パッケージリスト
     └── hashes.yaml          既知悪意ファイルハッシュ
```

## `bootstrap.js` — 初回自動取得（`ensureIOCs`）

```
ensureIOCs()
 ├── ~/.muaddib/data/iocs.json が存在する → スキップ
 └── 存在しない → updateIOCs() を呼び出して取得
```

初回のみ実行され、ネットワーク取得に失敗してもスキャン自体は継続します（`iocs-compact.json` はパッケージに同梱されているため最低限の検知は可能）。

## `updater.js` — IOC の更新と読み込み

### `updateIOCs()` — IOC データ更新

以下の 4 ステップで IOC を更新します：

```
updateIOCs()
 ├─ [1/4] iocs-compact.json を展開（expandCompactIOCs）
 ├─ [2/4] YAML IOC を読み込み（loadYAMLIOCs）
 ├─ [3/4] GitHub + OSV API から IOC をダウンロード（並列）
 │         - scrapeShaiHuludDetector()
 │         - scrapeDatadogIOCs()
 │         - scrapeOSVLightweightAPI()
 └─ [4/4] ~/.muaddib/data/iocs.json に保存 + インデックス構築
```

### `loadCachedIOCs()` — IOC 読み込み（スキャン時）

スキャン実行時に IOC データをメモリにロードします。読み込み優先順位：

1. `~/.muaddib/data/iocs.json`（更新済みフル版）
2. `src/ioc/data/iocs.json`（パッケージ同梱フル版）
3. `src/ioc/data/iocs-compact.json` を展開（コンパクト版）

ロード後、以下のインデックスを構築してスキャン時の照合を高速化します：

| インデックス | 型 | 説明 |
|---|---|---|
| `npmPackagesMap` | `Map<name, Package[]>` | npm パッケージ名 → バージョンリスト |
| `pypiPackagesMap` | `Map<name, Package[]>` | PyPI パッケージ名 → バージョンリスト |
| `pypiWildcardPackages` | `Set<name>` | 全バージョンが悪意ある PyPI パッケージ名 |
| `hashSet` | `Set<sha256>` | 既知悪意ファイルのハッシュ値 |
| `markerSet` | `Set<string>` | マーカー文字列 |

### `checkIOCStaleness(days)` — 鮮度チェック

IOC DB が指定日数以上古い場合に警告文字列を返します（デフォルト: 30 日）。警告は `warnings` 配列に追加され、CLI に表示されます。

## `scraper.js` — 外部 IOC ソース

| 関数 | ソース | 説明 |
|---|---|---|
| `scrapeShaiHuludDetector()` | GenSecAI GitHub | npm 悪意パッケージリスト |
| `scrapeDatadogIOCs()` | DataDog GitHub | npm/PyPI 悪意パッケージリスト |
| `scrapeOSVLightweightAPI()` | OSV API | Go/npm/PyPI 脆弱性情報 |

## コンパクト IOC フォーマット

87% のパッケージはワイルドカード（全バージョン悪意）のため、コンパクト版では以下の形式で圧縮されています：

```json
{
  "npm": {
    "wildcards": ["malicious-pkg-1", "malicious-pkg-2"],
    "versioned": [{ "n": "pkg-name", "v": "1.2.3" }]
  },
  "pypi": { "wildcards": [...], "versioned": [...] },
  "hashes": ["sha256hex1", "sha256hex2"]
}
```

フル版の 112MB に対してコンパクト版は約 5MB で、パッケージに同梱できます。

## IOC データのスキャナ利用

| スキャナ | 利用する IOC |
|---|---|
| `dependencies.js` | `npmPackagesMap` (npm IOC 照合) |
| `hash.js` | `hashSet` (ファイルハッシュ照合) |
| `executor.js#matchPythonIOCs` | `pypiPackagesMap`, `pypiWildcardPackages` |

## 依存関係

```
src/ioc/updater.js
 ├── src/ioc/scraper.js
 ├── src/ioc/yaml-loader.js
 └── (node 標準モジュール: fs, path, os, crypto)
```
