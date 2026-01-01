# MUAD'DIB Threat Model

## Ce que MUAD'DIB detecte

### Attaques Supply Chain npm

| Technique | Detection | Confidence |
|-----------|-----------|------------|
| Packages malveillants connus | Hash SHA256 + nom | HIGH |
| Shai-Hulud v1/v2/v3 | Marqueurs + fichiers + comportements | HIGH |
| event-stream (2018) | Nom + version | HIGH |
| Typosquatting | Liste de packages connus | MEDIUM |
| Protestware (node-ipc, colors) | Nom + version | HIGH |

### Comportements malveillants

| Technique | Detection | Confidence |
|-----------|-----------|------------|
| Vol de credentials (.npmrc, .ssh) | Analyse AST | HIGH |
| Exfiltration via env vars (GITHUB_TOKEN) | Analyse AST | HIGH |
| Execution de code distant (curl \| sh) | Pattern matching | HIGH |
| Reverse shell | Pattern matching | HIGH |
| Dead man's switch (rm -rf $HOME) | Pattern matching | HIGH |
| Code obfusque | Heuristiques | MEDIUM |

### Flux de donnees suspects

| Technique | Detection | Confidence |
|-----------|-----------|------------|
| Lecture credential + envoi reseau | Analyse dataflow | HIGH |
| Acces process.env + fetch/request | Analyse dataflow | HIGH |

## Ce que MUAD'DIB NE detecte PAS

### Limitations connues

| Technique | Raison |
|-----------|--------|
| Malware polymorphe | Pas d'analyse dynamique |
| Obfuscation avancee | Heuristiques limitees |
| Zero-day (packages inconnus) | Base IOC reactive |
| Attaques via binaires natifs | Pas d'analyse binaire |
| Backdoors subtiles | Pas de review de code semantique |
| Time bombs (declenchement differe) | Pas d'analyse temporelle |

### Faux negatifs potentiels

- Code malveillant dans des fichiers non-JS (WASM, binaires)
- Exfiltration via DNS ou autres canaux couverts
- Malware qui detecte l'environnement d'analyse
- Attaques multi-etapes avec payload distant

## Hypotheses

1. **Le code source est disponible** — MUAD'DIB analyse le code, pas les binaires
2. **Les IOCs sont a jour** — La detection depend de la base IOC
3. **L'attaquant utilise des techniques connues** — Zero-days passent a travers
4. **Le scan est execute avant l'installation** — Apres `npm install`, c'est trop tard si preinstall a execute

## Architecture de detection
```
┌─────────────────────────────────────────────────────────────┐
│                      MUAD'DIB Scanner                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  IOC Match  │  │  AST Parse  │  │  Pattern Matching   │  │
│  │  (hashes,   │  │  (acorn)    │  │  (shell, scripts)   │  │
│  │  packages)  │  │             │  │                     │  │
│  └──────┬──────┘  └──────┬──────┘  └──────────┬──────────┘  │
│         │                │                     │             │
│         v                v                     v             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                   Dataflow Analysis                      ││
│  │            (credential read -> network send)             ││
│  └─────────────────────────────────────────────────────────┘│
│         │                │                     │             │
│         v                v                     v             │
│  ┌─────────────────────────────────────────────────────────┐│
│  │                   Threat Enrichment                      ││
│  │         (rules, MITRE ATT&CK, playbooks)                 ││
│  └─────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────┘
```

## Mapping MITRE ATT&CK

| Technique | ID | Detection MUAD'DIB |
|-----------|----|--------------------|
| Credentials in Files | T1552.001 | AST analysis |
| Command and Scripting Interpreter | T1059 | Pattern matching |
| Supply Chain Compromise | T1195.002 | IOC matching |
| Obfuscated Files | T1027 | Heuristics |
| Exfiltration Over C2 Channel | T1041 | Dataflow analysis |
| Data Destruction | T1485 | Pattern matching |
| Ingress Tool Transfer | T1105 | Pattern matching |

## Recommandations

### Pour les utilisateurs

1. Executer `muaddib scan .` AVANT `npm install`
2. Mettre a jour les IOCs regulierement (`muaddib update`)
3. Utiliser le mode `--explain` pour comprendre les detections
4. Integrer dans CI/CD avec sortie SARIF

### Pour les equipes securite

1. Completer avec une analyse dynamique (sandbox)
2. Monitorer les nouveaux packages avant adoption
3. Utiliser `--sarif` pour integration SIEM
4. Contribuer des IOCs via PR sur le repo

## Contacts

- Repository: https://github.com/DNSZLSK/muad-dib
- Issues: https://github.com/DNSZLSK/muad-dib/issues