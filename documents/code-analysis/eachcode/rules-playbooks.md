# src/rules/index.js + src/response/playbooks.js — ルールとプレイブック

## 概要

`src/rules/index.js` は検知ルールのメタデータ（ID・名前・severity・信頼度・説明・MITRE ATT&CK マッピング）を定義するレジストリです。`src/response/playbooks.js` は各ルールに対応するインシデント対応手順（プレイブック）を定義します。

## `src/rules/index.js`

### エクスポート

```js
module.exports = { RULES, getRule };
```

### `RULES` オブジェクトの構造

```js
{
  [ruleKey]: {
    id: 'MUADDIB-XXX-NNN',   // ルール ID（一意）
    name: string,             // 人間が読める名前
    severity: string,         // 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    confidence: string,       // 'high' | 'medium' | 'low'
    description: string,      // 検知理由の説明
    references: string[],     // 関連リンク
    mitre: string             // MITRE ATT&CK タクティクス ID (例: 'T1105')
  }
}
```

### ルール数

| 種別 | 数 |
|---|---|
| 通常ルール | 195 |
| PARANOID ルール | 5 |
| **合計** | **200** |

### ルール ID の命名規則

| プレフィックス | スキャナ・検知カテゴリ |
|---|---|
| `MUADDIB-AST-xxx` | AST 解析（eval, exec, 動的 require 等） |
| `MUADDIB-SHELL-xxx` | シェルスクリプト（reverse shell, curl pipe 等） |
| `MUADDIB-PKG-xxx` | package.json スクリプト |
| `MUADDIB-OBF-xxx` | 難読化検出 |
| `MUADDIB-DEP-xxx` | 依存関係・IOC 照合 |
| `MUADDIB-FLOW-xxx` | データフロー解析 |
| `MUADDIB-TYPO-xxx` | タイポスクワット検出 |
| `MUADDIB-HASH-xxx` | 既知悪意ファイルハッシュ |
| `MUADDIB-PYPI-xxx` | PyPI 悪意パッケージ・タイポスクワット |
| `MUADDIB-AICONF-xxx` | AI 設定ファイルへのプロンプトインジェクション |
| `MUADDIB-GHA-xxx` | GitHub Actions ワークフロー解析 |

### `getRule(type)` — ルール取得

```js
getRule('eval_usage')
// → { id: 'MUADDIB-AST-001', name: 'Eval Usage', severity: 'CRITICAL', ... }
```

`type` に対応するルールが存在しない場合はデフォルトオブジェクトを返します（スキャナがクラッシュしないよう保護）。

### processor.js でのエンリッチ利用

```js
const rule = getRule(t.type);
const confFactor = { high: 1.0, medium: 0.85, low: 0.6 }[rule.confidence];
const points = Math.round((getSeverityWeights()[t.severity] || 0) * confFactor);
// 脅威に rule_id, rule_name, confidence, references, mitre, points を付加
```

---

## `src/response/playbooks.js`

### エクスポート

```js
module.exports = { PLAYBOOKS, getPlaybook };
```

### `PLAYBOOKS` オブジェクトの構造

```js
{
  [ruleKey]: string  // インシデント対応手順テキスト
}
```

### `getPlaybook(type)` — プレイブック取得

`type` に対応するプレイブック文字列を返します。対応するプレイブックがない場合は空文字列を返します。

`--explain` オプション時に CLI に表示されます：

```
[PLAYBOOK] eval_usage
  Remove eval() calls. If dynamic code execution is required, consider safer
  alternatives like Function constructors with sanitized input. Isolate and
  quarantine the package immediately.
```

### ルールとプレイブックの対応

各ルールキー（`eval_usage`, `reverse_shell` 等）に対してルールメタデータとプレイブックが 1 対 1 で対応します。新しいルールを追加する際は両方への追加が必要です。

---

## ルール・プレイブックの追加手順

新しいルールを追加する場合は以下のファイルを編集します：

### 1. `src/rules/index.js` への追加

```js
my_new_rule: {
  id: 'MUADDIB-AST-099',
  name: 'My New Detection',
  severity: 'HIGH',
  confidence: 'high',
  description: 'Detects suspicious XYZ pattern',
  references: ['https://example.com/reference'],
  mitre: 'T1059'
}
```

### 2. `src/response/playbooks.js` への追加

```js
my_new_rule: 'Investigate the XYZ usage and quarantine the package if confirmed malicious.'
```

### 3. テストの追加

```js
// tests/ にテストケースを追加
test('detects my new rule', () => {
  // tests/samples/ にフィクスチャを配置してスキャン
});
```

## 依存関係

```
src/rules/index.js
 └── (外部依存なし)

src/response/playbooks.js
 └── (外部依存なし)
```
