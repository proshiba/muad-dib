# src/scoring.js — リスクスコアリング

## 概要

MUAD'DIB のリスクスコア計算・FP（誤検知）削減・Compound ブースト・設定上書きを担当するコアモジュールです。スキャン結果の最終的なリスクレベル判定を行います。

## エクスポート

```js
module.exports = {
  calculateRiskScore,
  applyFPReductions,
  applyCompoundBoosts,
  isPackageLevelThreat,
  computeGroupScore,
  applyConfigOverrides,
  resetConfigOverrides,
  getSeverityWeights,
  getRiskThresholds
};
```

## スコアリング定数

### `SEVERITY_WEIGHTS`（severity ごとのスコアウェイト）

| Severity | デフォルト値 | 解説 |
|---|---|---|
| `CRITICAL` | 25 | 4 件で最大スコア (100) |
| `HIGH` | 10 | 10 件で最大スコア |
| `MEDIUM` | 3 | |
| `LOW` | 1 | |

### `RISK_THRESHOLDS`（リスクレベル判定しきい値）

| レベル | しきい値 | 意味 |
|---|---|---|
| `CRITICAL` | >= 75 | 即時対応が必要 |
| `HIGH` | >= 50 | 優先調査 |
| `MEDIUM` | >= 25 | 監視 |
| `LOW` | > 0 | 情報 |
| `SAFE` | 0 | 脅威なし |

### `CONFIDENCE_FACTORS`（信頼度係数）

| Confidence | 係数 | 説明 |
|---|---|---|
| `high` | 1.0 | 高確信度（IOC 照合、`eval`、シェルインジェクション等） |
| `medium` | 0.85 | 中確信度（ライフサイクルスクリプト、難読化等） |
| `low` | 0.6 | 低確信度（情報提供レベルの検出） |

## `calculateRiskScore(deduped, intentResult)` — スコア計算

### Per-File Max スコアリング方式（v2.2.11）

各ファイルのスコアを独立して計算し、最大ファイルスコアにパッケージレベルスコアを加算します：

```
riskScore = min(100, max(fileScores) + packageLevelScore)
```

**パッケージレベル脅威**（`PACKAGE_LEVEL_TYPES`）はファイルに紐づかず、パッケージスコアに加算されます（例: `lifecycle_script`, `typosquat_detected`, `known_malicious_package`）。

**ファイルスコア**は同一ファイルの脅威ポイントの合計で、`MAX_FILE_SCORE`（50）でキャップされます。

### Intent ボーナス

`buildIntentPairs()` が source-sink ペアを検出した場合、intent ボーナスが `globalRiskScore` に加算されます。

### 特別な上限

| 脅威タイプ | 上限 | 理由 |
|---|---|---|
| `prototype_hook`（MEDIUM） | 15 pt | フレームワーク拡張のノイズを抑制 |
| `suspicious_dataflow`（MEDIUM） | 3 pt | 単独では弱いシグナル（Compound が本シグナル） |

## `applyFPReductions(deduped, reachableFiles, packageName, packageDeps)` — FP 削減

正規フレームワークやパターンが大量の特定脅威タイプを生成する場合に severity をダウングレードします。

**主な削減ルール（例）**：
- テスト/ビルドディレクトリのファイルは削減対象
- 到達不可能ファイルの脅威は severity をダウングレード
- 同一タイプが多数ある場合に低 severity のものを削減

## `applyCompoundBoosts(deduped)` — Compound ブースト

FP 削減後も残っている脅威が悪意の高い組み合わせを示す場合に合成 CRITICAL 脅威を追加します。これは FP 削減で個別に抑制された後でも強いシグナルを回復するためです。

## 設定可能性

`.muaddibrc.json` の `severityWeights` / `riskThresholds` で各値を上書きできます：

```json
{
  "severityWeights": { "critical": 30, "high": 15 },
  "riskThresholds": { "critical": 80 }
}
```

設定はスキャン終了後に `resetConfigOverrides()` でリセットされます（スキャン間の状態リーク防止）。

## 依存関係

```
src/scoring.js
 ├── src/rules/index.js              (getRule — ルール信頼度参照)
 └── src/monitor/classify.js         (HIGH_CONFIDENCE_MALICE_TYPES)
```
