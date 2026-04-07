# MUAD'DIB コード解説

## 1. プロジェクトの基本機能

MUAD'DIB (`muaddib-scanner`) は npm および PyPI/Python パッケージを対象とした **サプライチェーン攻撃検知ツール**です。

### 主な機能

| 機能 | 説明 |
|---|---|
| 静的スキャン | 14 の並列スキャナが package.json・JS/TS コード・シェルスクリプト・Python 依存関係を解析 |
| IOC マッチング | 225,000+ の既知悪意パッケージ DB (npm / PyPI) と照合 |
| AST 解析 | acorn を用いた抽象構文木解析で危険な関数呼び出しや難読化コードを検出 |
| データフロー解析 | クレデンシャル読み取り → ネットワーク送信などの不審なデータの流れを追跡 |
| タイポスクワット検出 | Levenshtein 距離でポピュラーパッケージに酷似した名前のパッケージを検出 |
| 難読化解析 | 難読化コードを自動でデオブファスケートしてから解析 |
| クロスファイルフロー | モジュールグラフを構築し、ファイルをまたぐデータフロー（tainted export → sink）を検出 |
| AI 設定インジェクション検出 | `.cursorrules` や `CLAUDE.md` 等の AI エージェント設定ファイルへのプロンプトインジェクションを検出 |
| GitHub Actions 解析 | ワークフロー定義内の不審なシェルコマンドを検出 |
| エントロピー解析 | 高エントロピー文字列（埋め込みシークレット等）を検出 |
| サンドボックス連携 | Docker / gVisor サンドボックスでのダイナミック解析（`--auto-sandbox`） |
| ML 分類器 | XGBoost ベースの機械学習モデルによる誤検知削減 |
| 複合スコアリング | Compound ルール・信頼度重みづけで最終リスクスコア (0〜100) を算出 |
| 出力形式 | CLI テキスト / JSON / HTML / SARIF に対応、Webhook 送信も可能 |

---

## 2. インストール及び実行方法

### インストール

#### npm からインストール（推奨）

```bash
npm install -g muaddib-scanner
```

#### ソースからインストール

```bash
git clone https://github.com/DNSZLSK/muad-dib
cd muad-dib
npm install
npm link
```

### 基本スキャン

```bash
# カレントディレクトリをスキャン
muaddib scan .

# 特定ディレクトリを指定
muaddib scan /path/to/project

# JSON 形式で出力
muaddib scan . --json

# HTML レポートを生成
muaddib scan . --html report.html

# SARIF 形式で出力（CI/CD 向け）
muaddib scan . --sarif results.sarif

# 詳細説明モード（ルール詳細・プレイブックを表示）
muaddib scan . --explain

# パラノイドモード（さらに厳格な検査）
muaddib scan . --paranoid

# 自動サンドボックス解析
muaddib scan . --auto-sandbox
```

### IOC データベースの更新

```bash
muaddib update
```

### 開発・テスト用コマンド

```bash
npm test          # 全テスト実行（3068 テスト、66 ファイル）
npm run lint      # ESLint による静的解析
npm run scan      # セルフスキャン
npm run update    # 最新 IOC をダウンロード
```

---

## 3. main はどこか

### CLI エントリポイント

```
bin/muaddib.js
```

- CLI 引数を解析（yargs 非使用、手書きパーサ）
- `evaluate` コマンド時はメモリフラグ付きで自身を再起動
- 各コマンドを対応モジュールに委譲（`scan` → `src/index.js`）

### ライブラリエントリポイント

```
src/index.js
```

- `package.json` の `"main"` フィールドに設定されているライブラリ本体
- `run(targetPath, options)` 関数を export
- パイプライン 4 フェーズを順に実行（詳細は次節）

---

## 4. ロジックフロー

スキャン処理は 4 フェーズのパイプラインで構成されます。

```
bin/muaddib.js
    │
    └─► src/index.js : run(targetPath, options)
            │
            ├─ Phase 1: src/pipeline/initializer.js
            │       ・パス検証・設定ファイル読み込み
            │       ・IOC DB 読み込み / 鮮度チェック
            │       ・Python プロジェクト検出 (requirements.txt 等)
            │
            ├─ Phase 2: src/pipeline/executor.js : execute()
            │       ・モジュールグラフ構築 (pre-analysis, 5s タイムアウト)
            │           src/scanner/module-graph/
            │               buildModuleGraph → annotateTaintedExports
            │               → annotateSinkExports → detectCrossFileFlows
            │               → detectCallbackCrossFileFlows
            │               → detectEventEmitterFlows
            │       ・13 スキャナを Promise.allSettled で並列実行
            │           scanPackageJson    (src/scanner/package.js)
            │           scanShellScripts   (src/scanner/shell.js)
            │           analyzeAST         (src/scanner/ast.js)
            │           detectObfuscation  (src/scanner/obfuscation.js)
            │           scanDependencies   (src/scanner/dependencies.js)
            │           scanHashes         (src/scanner/hash.js)
            │           analyzeDataFlow    (src/scanner/dataflow.js)
            │           scanTyposquatting  (src/scanner/typosquat.js)
            │           scanGitHubActions  (src/scanner/github-actions.js)
            │           matchPythonIOCs    (IOC DB 照合)
            │           checkPyPITyposquatting
            │           scanEntropy        (src/scanner/entropy.js)
            │           scanAIConfig       (src/scanner/ai-config.js)
            │       ・500 ファイル超のオーバーフロー → クイックスキャン
            │       ・paranoid モード / temporal モード の追加スキャン
            │
            ├─ Phase 3: src/pipeline/processor.js : process()
            │       ・Auto-sandbox トリガー判定
            │       ・脅威の重複排除 (file + type + message キー)
            │       ・Compound ルール評価 (複数検知の組み合わせ)
            │       ・FP 削減 (src/scoring.js : applyFPReductions)
            │       ・Intent グラフ解析 (src/intent-graph.js)
            │       ・ルール・プレイブックでの脅威エンリッチメント
            │           src/rules/index.js  → severity / description / MITRE
            │           src/response/playbooks.js → 対応手順
            │       ・リスクスコア算出
            │           riskScore = min(100, max(ファイルスコア) + パッケージレベルスコア)
            │           CRITICAL=25, HIGH=10, MEDIUM=3, LOW=1
            │           信頼度係数: high=1.0, medium=0.85, low=0.6
            │
            └─ Phase 4: src/pipeline/outputter.js : output()
                    ・CLI テキスト / JSON / HTML / SARIF 出力
                    ・Webhook 送信
                    ・終了コード設定 (--fail-on による閾値)
```

---

## 5. どこに検知ルールが記載されているか

### ルール定義（ID / name / severity / description / MITRE）

```
src/rules/index.js
```

全 200 ルール（195 通常 + 5 PARANOID）が `RULES` オブジェクトとして定義されています。

```js
// 例: MUADDIB-SHELL-001
curl_exec: {
  id: 'MUADDIB-SHELL-001',
  name: 'Remote Code Execution via Curl',
  severity: 'CRITICAL',
  confidence: 'high',
  description: 'Telecharge et execute du code distant via curl | sh',
  references: ['https://blog.phylum.io/shai-hulud-npm-worm'],
  mitre: 'T1105'
}
```

### ルール ID の命名規則

| プレフィックス | スキャナ |
|---|---|
| `MUADDIB-AST-xxx` | AST 解析（危険な関数呼び出し・動的 require 等） |
| `MUADDIB-SHELL-xxx` | シェルスクリプト解析（reverse shell・curl pipe 等） |
| `MUADDIB-PKG-xxx` | package.json スクリプト解析 |
| `MUADDIB-OBF-xxx` | 難読化検出 |
| `MUADDIB-DEP-xxx` | 依存関係・IOC マッチング |
| `MUADDIB-FLOW-xxx` | データフロー解析 |
| `MUADDIB-TYPO-xxx` | タイポスクワット検出 |
| `MUADDIB-HASH-xxx` | 既知悪意ファイルハッシュ照合 |
| `MUADDIB-PYPI-xxx` | PyPI 悪意パッケージ・タイポスクワット |
| `MUADDIB-AICONF-xxx` | AI 設定ファイルへのプロンプトインジェクション |
| `MUADDIB-GHA-xxx` | GitHub Actions ワークフロー解析 |

### 対応プレイブック（レスポンス手順）

```
src/response/playbooks.js
```

各ルール type に対応する対応手順テキストが定義されています（`--explain` モードで表示）。

### IOC データベース

```
src/ioc/data/iocs-compact.json   # コミット済みコンパクト版 (~5MB)
src/ioc/data/iocs.json           # フル版 (112MB, .gitignore)
src/ioc/updater.js               # IOC の更新・読み込み
src/ioc/scraper.js               # IOC のスクレイピング
```

### スキャナ本体（検知パターンの実装）

```
src/scanner/
  ast.js              # AST 解析エンジン（acorn）
  ast-detectors/      # AST ハンドラ群（CallExpression, Literal 等）
  shell.js            # シェルスクリプトの正規表現パターン
  package.js          # package.json スクリプトの正規表現パターン
  obfuscation.js      # 難読化検出
  dependencies.js     # 依存関係の IOC 照合・URL 検出
  entropy.js          # Shannon エントロピー計算
  typosquat.js        # Levenshtein 距離によるタイポスクワット
  dataflow.js         # データフロー解析
  hash.js             # SHA256 ハッシュ照合
  ai-config.js        # AI 設定ファイル解析
  github-actions.js   # GitHub Actions YAML 解析
  python.js           # Python プロジェクト検出
```

---

## 6. 改変方法のサンプル

### a. 新しいルールの追加方法

新しい検知ルールを追加するには、以下の 5 ステップが必要です。

#### ステップ 1: `src/rules/index.js` にルール定義を追加

```js
// src/rules/index.js の RULES オブジェクトに追記
my_new_detection: {
  id: 'MUADDIB-AST-099',
  name: 'My New Detection',
  severity: 'HIGH',           // CRITICAL / HIGH / MEDIUM / LOW
  confidence: 'high',         // high / medium / low
  description: 'Detects suspicious XYZ pattern',
  references: [
    'https://example.com/attack-reference'
  ],
  mitre: 'T1059'
}
```

#### ステップ 2: `src/response/playbooks.js` に対応手順を追加

```js
// src/response/playbooks.js の PLAYBOOKS オブジェクトに追記
my_new_detection:
  'Investigate the XYZ usage. Check if the data destination is legitimate.',
```

#### ステップ 3: 対応するスキャナに検知ロジックを実装

例として `src/scanner/ast-detectors/handle-call-expression.js` に新しいパターンを追加する場合：

```js
// 既存の CallExpression ハンドラの検出リストに追加
// または新しいスキャナファイルを src/scanner/my-scanner.js として作成し、
// targetPath を受け取って threats 配列を返す関数を export する
function scanMyPattern(targetPath) {
  const threats = [];
  // ... 検知ロジック ...
  threats.push({
    type: 'my_new_detection',   // rules/index.js のキーと一致させる
    severity: 'HIGH',
    message: 'Suspicious XYZ detected in ...',
    file: relativeFilePath      // path.relative() で相対パスにする
  });
  return threats;
}
module.exports = { scanMyPattern };
```

#### ステップ 4: `src/pipeline/executor.js` にスキャナを登録

```js
// executor.js の先頭 import に追加
const { scanMyPattern } = require('../scanner/my-scanner.js');

// SCANNER_NAMES 配列に追加
const SCANNER_NAMES = [
  // ... 既存のスキャナ名 ...
  'scanMyPattern'   // 追加
];

// Promise.allSettled の配列に追加
const settledResults = await Promise.allSettled([
  // ... 既存のスキャナ呼び出し ...
  yieldThen(() => scanMyPattern(targetPath))   // 追加
]);

// 結果の分解代入に追加
const [
  // ... 既存の変数 ...
  myPatternThreats   // 追加
] = scanResult;

// threats 配列への spread に追加
const threats = [
  // ... 既存の threats ...
  ...myPatternThreats   // 追加
];
```

#### ステップ 5: テストを追加

```js
// tests/ 配下の適切なテストファイルに追加
// または tests/my-scanner.test.js を新規作成

test('detects my new pattern', () => {
  // tests/samples/my-scanner/ にテスト用フィクスチャを配置
  const result = runScan('tests/samples/my-scanner/malicious-sample');
  assertIncludes(result, 'MUADDIB-AST-099');
});

test('no false positive on benign code', () => {
  const result = runScan('tests/samples/my-scanner/benign-sample');
  assert(!result.includes('MUADDIB-AST-099'), 'should not trigger on benign code');
});
```

---

### b. 既存ルールの検知理由（description）や severity の変更方法

既存ルールのメタデータは `src/rules/index.js` の該当エントリを編集するだけで変更できます。

#### severity の変更例

`MUADDIB-AST-003`（Dangerous Function Call）を `MEDIUM` から `HIGH` に変更する場合：

```js
// src/rules/index.js
dangerous_call_exec: {
  id: 'MUADDIB-AST-003',
  name: 'Dangerous Function Call',
  severity: 'HIGH',           // 変更前: 'MEDIUM' → 変更後: 'HIGH'
  confidence: 'medium',
  description: 'Appel a une fonction dangereuse (exec, spawn, eval, Function)',
  references: [
    'https://owasp.org/www-community/attacks/Command_Injection'
  ],
  mitre: 'T1059'
}
```

#### description（検知理由）の変更例

```js
// src/rules/index.js
lifecycle_script: {
  id: 'MUADDIB-PKG-001',
  name: 'Suspicious Lifecycle Script',
  severity: 'MEDIUM',
  confidence: 'medium',
  description: 'Suspicious preinstall/postinstall script detected in package.json',  // 任意のテキストに変更
  references: [
    'https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm'
  ],
  mitre: 'T1195.002'
}
```

#### スコアリングの重みを変更したい場合

重大度ごとのスコアリング重みは `src/scoring.js` の定数で管理されています：

```js
// src/scoring.js
const SEVERITY_WEIGHTS = {
  CRITICAL: 25,   // 4 件で最大スコア (100)
  HIGH: 10,       // 10 件で最大スコア
  MEDIUM: 3,
  LOW: 1
};

const RISK_THRESHOLDS = {
  CRITICAL: 75,   // >= 75: 即時対応
  HIGH: 50,       // >= 50: 優先調査
  MEDIUM: 25      // >= 25: 監視
};
```

これらの値を変更することでリスクスコアの計算に影響を与えることができます。変更後は必ず `npm test` で回帰テストを実行してください。
