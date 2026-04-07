# src/ml/classifier.js — ML 分類器

## 概要

XGBoost ベースの機械学習モデルをピュア JavaScript で実装した誤検知削減分類器です。静的スキャンで生成されたリスクスコアが「グレーゾーン」（スコア 20-34）のパッケージについて、より精度の高い判定を行います。

## エクスポート

```js
module.exports = {
  classify,
  isModelAvailable,
  isBundlerModelAvailable,
  resetModel
};
```

## ガードレール設計

ML 分類器には誤抑制を防ぐための厳格なガードレールが設定されています：

```
スコア < 20      → clean（T1 しきい値未満）
スコア >= 35:
  1. HC_TYPES 存在 → bypass（絶対に抑制しない）
  2. バンドラーモデル利用可能 → バンドラーモデルで判定
  3. バンドラーモデル不在 → bypass
スコア 20-34（T1 ゾーン）:
  1. モデル不在 → bypass
  2. HC_TYPES 存在 → bypass
  3. モデルが fp と判定 → fp（誤検知として抑制）
  4. その他 → bypass（抑制しない）
```

## HC_TYPES（高確信度悪意タイプ）

以下の脅威タイプは ML によって絶対に抑制されません：

| 脅威タイプ | 理由 |
|---|---|
| `known_malicious_package` | IOC 直接一致 |
| `known_malicious_hash` | ハッシュ直接一致 |
| `pypi_malicious_package` | PyPI IOC 直接一致 |
| `typosquat_detected` | タイポスクワット確認済み |
| `pypi_typosquat_detected` | PyPI タイポスクワット確認済み |
| `reverse_shell` | 高確信度シェル検出 |
| `binary_dropper` | バイナリ投下 |
| `staged_binary_payload` | ステージングバイナリ |

## モデル構成

```
src/ml/
 ├── classifier.js        メイン分類器（ガードレール + 推論）
 ├── feature-extractor.js 脅威配列から特徴量ベクトルを生成
 ├── model-trees.js       バンドル済み XGBoost 決定木（生成物）
 └── model-bundler.js     モデルバンドルツール
```

### モデルの種類

| モデル | 目的 |
|---|---|
| メインモデル | T1 ゾーン (20-34) の誤検知削減 |
| バンドラーモデル | minify/bundle 済みパッケージの誤検知削減 |
| シャドーモデル | 本番影響なしの実験的モデル（統計収集のみ） |

## `classify(threats, score)` の動作

```
classify(threats, score)
 │
 ├─ score < 20 → { prediction: 'clean' }
 ├─ score >= 35 かつ HC_TYPES あり → { prediction: 'bypass' }
 ├─ score >= 35 かつ バンドラーモデルあり → バンドラー推論
 ├─ T1 ゾーン (20-34):
 │   ├─ モデルなし → { prediction: 'bypass' }
 │   ├─ HC_TYPES あり → { prediction: 'bypass' }
 │   └─ モデル推論 → { prediction: 'fp' | 'bypass' }
 └─ 戻り値: { prediction, confidence, features }
```

## `feature-extractor.js` — 特徴量抽出

脅威配列と集約統計から ML モデルへの入力特徴量ベクトルを生成します。

主な特徴量：

| 特徴量 | 説明 |
|---|---|
| severity カウント | CRITICAL/HIGH/MEDIUM/LOW の件数 |
| タイプ分布 | 各脅威タイプの出現数 |
| ファイル多様性 | 脅威が存在するファイル数 |
| パッケージレベル脅威の有無 | lifecycle_script 等の有無 |
| 難読化スコア | 難読化関連脅威の重み付き合計 |

## ML モデルのトレーニング

```
src/ml/train-xgboost.py     XGBoost モデルのトレーニングスクリプト（Python）
src/ml/train-bundler-detector.py  バンドラーモデルのトレーニング
```

トレーニングデータは `ml-retrain/` ディレクトリに格納されます。

## 依存関係

```
src/ml/classifier.js
 └── src/ml/feature-extractor.js
      └── (外部依存なし)
```
