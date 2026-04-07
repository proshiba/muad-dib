# MUAD'DIB ソースコード解説 — モジュール関係図

本フォルダには、MUAD'DIB の主要ソースファイルごとのコード解説ドキュメントが格納されています。

## ドキュメント一覧

| ファイル | 対応ソース |
|---|---|
| [src-index.md](./src-index.md) | `src/index.js` — ライブラリエントリポイント |
| [pipeline-initializer.md](./pipeline-initializer.md) | `src/pipeline/initializer.js` — Phase 1: 初期化 |
| [pipeline-executor.md](./pipeline-executor.md) | `src/pipeline/executor.js` — Phase 2: スキャン実行 |
| [pipeline-processor.md](./pipeline-processor.md) | `src/pipeline/processor.js` — Phase 3: 脅威処理 |
| [pipeline-outputter.md](./pipeline-outputter.md) | `src/pipeline/outputter.js` — Phase 4: 出力 |
| [scanner-ast.md](./scanner-ast.md) | `src/scanner/ast.js` — AST 解析エンジン |
| [scanner-dataflow.md](./scanner-dataflow.md) | `src/scanner/dataflow.js` — データフロー解析 |
| [scanner-module-graph.md](./scanner-module-graph.md) | `src/scanner/module-graph/` — クロスファイル解析 |
| [scoring.md](./scoring.md) | `src/scoring.js` — リスクスコアリング |
| [intent-graph.md](./intent-graph.md) | `src/intent-graph.js` — インテントグラフ解析 |
| [ioc.md](./ioc.md) | `src/ioc/` — IOC データベース管理 |
| [rules-playbooks.md](./rules-playbooks.md) | `src/rules/index.js` + `src/response/playbooks.js` |
| [ml-classifier.md](./ml-classifier.md) | `src/ml/classifier.js` — ML 分類器 |
| [scan-context.md](./scan-context.md) | `src/scan-context.js` — スキャンコンテキスト管理 |

---

## システム全体の構成図

```mermaid
graph TD
    CLI["bin/muaddib.js<br/>(CLI エントリポイント)"]
    INDEX["src/index.js<br/>run()"]
    INIT["src/pipeline/initializer.js<br/>initialize()"]
    EXEC["src/pipeline/executor.js<br/>execute()"]
    PROC["src/pipeline/processor.js<br/>process()"]
    OUT["src/pipeline/outputter.js<br/>output()"]

    CLI --> INDEX
    INDEX --> INIT
    INDEX --> EXEC
    INDEX --> PROC
    INDEX --> OUT
```

---

## モジュール依存関係図（全体）

```mermaid
graph LR
    subgraph Pipeline
        INIT["initializer.js"]
        EXEC["executor.js"]
        PROC["processor.js"]
        OUTP["outputter.js"]
    end

    subgraph Scanners
        PKG["scanner/package.js"]
        SHELL["scanner/shell.js"]
        AST["scanner/ast.js"]
        OBF["scanner/obfuscation.js"]
        DEP["scanner/dependencies.js"]
        HASH["scanner/hash.js"]
        DF["scanner/dataflow.js"]
        TYPO["scanner/typosquat.js"]
        GHA["scanner/github-actions.js"]
        ENT["scanner/entropy.js"]
        AICFG["scanner/ai-config.js"]
        PY["scanner/python.js"]
        MG["scanner/module-graph/"]
        PAR["scanner/paranoid.js"]
    end

    subgraph Core
        SCORING["scoring.js"]
        INTENT["intent-graph.js"]
        CTX["scan-context.js"]
        RULES["rules/index.js"]
        PLAYS["response/playbooks.js"]
        IOC["ioc/updater.js"]
        ML["ml/classifier.js"]
        REACH["scanner/reachability.js"]
        DEOB["scanner/deobfuscate.js"]
    end

    subgraph Output
        FMT["output-formatter.js"]
        SARIF["sarif.js"]
        REPORT["report.js"]
    end

    INIT --> IOC
    INIT --> PY
    EXEC --> PKG & SHELL & AST & OBF & DEP & HASH & DF & TYPO & GHA & ENT & AICFG
    EXEC --> MG
    EXEC --> DEOB
    EXEC --> PAR
    PROC --> SCORING
    PROC --> INTENT
    PROC --> RULES
    PROC --> PLAYS
    PROC --> REACH
    PROC --> ML
    OUTP --> FMT
    FMT --> SARIF
    FMT --> REPORT
    CTX --> SCORING
```

---

## UML クラス図 — パイプラインコンポーネント

```mermaid
classDiagram
    class index {
        +run(targetPath, options) Promise~exitCode~
        +isPackageLevelThreat(type) bool
        +computeGroupScore(threats) number
    }

    class initializer {
        +initialize(targetPath, options) Promise~InitResult~
    }

    class executor {
        +execute(targetPath, options, pythonDeps, warnings) Promise~ExecResult~
        +matchPythonIOCs(deps, targetPath) Threat[]
        +checkPyPITyposquatting(deps, targetPath) Threat[]
    }

    class processor {
        +process(threats, targetPath, options, pythonDeps, warnings, scannerErrors) Promise~ProcessResult~
    }

    class outputter {
        +output(result, options, processed) Promise~number~
    }

    index --> initializer : calls initialize()
    index --> executor : calls execute()
    index --> processor : calls process()
    index --> outputter : calls output()
```

---

## UML クラス図 — スキャナ群

```mermaid
classDiagram
    class Scanner {
        <<interface>>
        +scan(targetPath) Threat[]
    }

    class PackageScanner {
        +scanPackageJson(targetPath) Threat[]
    }
    class ShellScanner {
        +scanShellScripts(targetPath) Threat[]
    }
    class ASTScanner {
        +analyzeAST(targetPath, options) Promise~Threat[]~
        -analyzeFile(content, filePath, basePath) Threat[]
    }
    class ObfuscationScanner {
        +detectObfuscation(targetPath) Threat[]
    }
    class DependencyScanner {
        +scanDependencies(targetPath) Threat[]
    }
    class HashScanner {
        +scanHashes(targetPath) Threat[]
    }
    class DataflowScanner {
        +analyzeDataFlow(targetPath, options) Promise~Threat[]~
        -buildTaintMap(ast) Map
        -analyzeSinks(ast, taintMap) Threat[]
    }
    class TyposquatScanner {
        +scanTyposquatting(targetPath) Threat[]
        +findPyPITyposquatMatch(name) Match
    }
    class GitHubActionsScanner {
        +scanGitHubActions(targetPath) Threat[]
    }
    class EntropyScanner {
        +scanEntropy(targetPath, options) Promise~Threat[]~
    }
    class AIConfigScanner {
        +scanAIConfig(targetPath) Threat[]
    }
    class PythonScanner {
        +detectPythonProject(targetPath) PythonDep[]
        +normalizePythonName(name) string
    }
    class ModuleGraphScanner {
        +buildModuleGraph(targetPath) Graph
        +annotateTaintedExports(graph) TaintedMap
        +annotateSinkExports(graph) SinkMap
        +detectCrossFileFlows(graph, tainted, sinks) Flow[]
        +detectCallbackCrossFileFlows(graph, tainted, sinks) Flow[]
        +detectEventEmitterFlows(graph, tainted, sinks) Flow[]
    }

    Scanner <|.. PackageScanner
    Scanner <|.. ShellScanner
    Scanner <|.. ASTScanner
    Scanner <|.. ObfuscationScanner
    Scanner <|.. DependencyScanner
    Scanner <|.. HashScanner
    Scanner <|.. DataflowScanner
    Scanner <|.. TyposquatScanner
    Scanner <|.. GitHubActionsScanner
    Scanner <|.. EntropyScanner
    Scanner <|.. AIConfigScanner
    Scanner <|.. PythonScanner
    Scanner <|.. ModuleGraphScanner
```

---

## UML クラス図 — スコアリング・ルール・ML

```mermaid
classDiagram
    class scoring {
        -SEVERITY_WEIGHTS: object
        -RISK_THRESHOLDS: object
        -CONFIDENCE_FACTORS: object
        +calculateRiskScore(threats, intentResult) ScoreResult
        +applyFPReductions(threats, reachableFiles, pkgName, pkgDeps) void
        +applyCompoundBoosts(threats) void
        +applyConfigOverrides(config) void
        +resetConfigOverrides() void
        +getSeverityWeights() object
        +isPackageLevelThreat(type) bool
    }

    class intentGraph {
        -SOURCE_TYPES: object
        -SDK_ENV_DOMAIN_MAP: object[]
        +buildIntentPairs(threats, targetPath) IntentResult
        -classifySource(threat) string
        -classifySink(threat) string
        -isSDKPattern(envVar, destination) bool
    }

    class rulesIndex {
        -RULES: object
        +getRule(type) Rule
    }

    class playbooks {
        -PLAYBOOKS: object
        +getPlaybook(type) string
    }

    class MLClassifier {
        -HC_TYPES: Set
        +classify(threats, score) ClassifyResult
        +isModelAvailable() bool
        -loadModel() Model
    }

    class featureExtractor {
        +extractFeatures(threats) Features
    }

    scoring --> rulesIndex : getRule()
    processor --> scoring : calculateRiskScore()
    processor --> intentGraph : buildIntentPairs()
    processor --> rulesIndex : getRule()
    processor --> playbooks : getPlaybook()
    processor --> MLClassifier : classify()
    MLClassifier --> featureExtractor : extractFeatures()
```

---

## UML クラス図 — IOC システム

```mermaid
classDiagram
    class iocUpdater {
        +updateIOCs() Promise~void~
        +loadCachedIOCs() IOCData
        +checkIOCStaleness(days) string|null
        -expandCompactIOCs(compact) IOCData
        -mergeIOCs(base, additional) void
        -buildIndexes(iocs) IndexedIOCs
    }

    class iocBootstrap {
        +ensureIOCs() Promise~void~
    }

    class iocScraper {
        +scrapeShaiHuludDetector() Promise~IOCData~
        +scrapeDatadogIOCs() Promise~IOCData~
        +scrapeOSVLightweightAPI() Promise~IOCData~
    }

    class iocYAMLLoader {
        +loadYAMLIOCs() YAMLIOCs
    }

    class IOCData {
        +packages: Package[]
        +pypi_packages: PyPIPackage[]
        +hashes: string[]
        +markers: string[]
        +files: string[]
        +npmPackagesMap: Map
        +pypiPackagesMap: Map
        +pypiWildcardPackages: Set
    }

    iocBootstrap --> iocUpdater : updateIOCs()
    iocUpdater --> iocScraper : scrape*()
    iocUpdater --> iocYAMLLoader : loadYAMLIOCs()
    iocUpdater --> IOCData : builds
```

---

## UML クラス図 — AST 検出器サブシステム

```mermaid
classDiagram
    class ASTScanner {
        +analyzeAST(targetPath, options) Threat[]
        -analyzeFile(content, filePath, basePath) Threat[]
    }

    class ASTDetectors {
        +handleVariableDeclarator(node, state) void
        +handleCallExpression(node, state) void
        +handleImportExpression(node, state) void
        +handleNewExpression(node, state) void
        +handleLiteral(node, state) void
        +handleAssignmentExpression(node, state) void
        +handleMemberExpression(node, state) void
        +handleWithStatement(node, state) void
        +handlePostWalk(state) Threat[]
    }

    class ASTHelpers {
        +getCallName(node) string
        +isStringLiteral(node) bool
        +extractStringValue(node) string
    }

    class Deobfuscator {
        +deobfuscate(content, filePath) string
    }

    class AnalyzeHelper {
        +analyzeWithDeobfuscation(targetPath, analyzeFn, options) Threat[]
    }

    ASTScanner --> ASTDetectors : delegates each node type
    ASTScanner --> AnalyzeHelper : analyzeWithDeobfuscation()
    AnalyzeHelper --> Deobfuscator : deobfuscate()
    ASTDetectors --> ASTHelpers : utilities
```

---

## データフロー図 — スキャン実行の流れ

```mermaid
sequenceDiagram
    participant CLI as bin/muaddib.js
    participant IDX as src/index.js
    participant INIT as initializer.js
    participant EXEC as executor.js
    participant PROC as processor.js
    participant OUT as outputter.js

    CLI->>IDX: run(targetPath, options)
    IDX->>INIT: initialize()
    INIT-->>IDX: {pythonDeps, configApplied, warnings}
    IDX->>EXEC: execute()
    Note over EXEC: 13スキャナを Promise.allSettled で並列実行
    EXEC-->>IDX: {threats, scannerErrors}
    IDX->>PROC: process()
    Note over PROC: 重複排除→Compound→FP削減→Intent→スコア計算
    PROC-->>IDX: {result, enrichedThreats, ...}
    IDX->>OUT: output()
    OUT-->>CLI: exitCode
```

---

## データフロー図 — 脅威オブジェクトのライフサイクル

```mermaid
flowchart LR
    A["Scanner が\nThreat を生成\n{type, severity,\nmessage, file}"]
    B["executor.js\n全スキャナ結果を\nマージ"]
    C["processor.js\n重複排除\ndedup[]"]
    D["Compound ルール\n評価\n(例: detached_credential_exfil)"]
    E["FP 削減\napplyFPReductions()"]
    F["Intent ペア\n分析\nbuildIntentPairs()"]
    G["ルールエンリッチ\nrule_id / mitre /\nplaybook / points"]
    H["リスクスコア計算\ncalculateRiskScore()"]
    I["最終 result\n{threats[], summary\n{riskScore, riskLevel}}"]

    A --> B --> C --> D --> E --> F --> G --> H --> I
```
