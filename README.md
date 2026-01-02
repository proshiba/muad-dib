<p align="center">
  <img src="MUADDIBLOGO.png" alt="MUAD'DIB Logo" width="200">
</p>

<h1 align="center">MUAD'DIB</h1>

<p align="center">
  <strong>Supply-chain threat detection & response for npm</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/npm/v/muaddib-scanner" alt="npm version">
  <img src="https://img.shields.io/npm/dt/muaddib-scanner" alt="npm downloads">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/node-%3E%3D18-brightgreen" alt="Node">
</p>

<p align="center">
  <a href="#installation">Installation</a> |
  <a href="#utilisation">Utilisation</a> |
  <a href="#features">Features</a> |
  <a href="#vs-code">VS Code</a> |
  <a href="#discord">Discord</a>
</p>

---

## Pourquoi MUAD'DIB ?

Les attaques supply chain npm explosent. Shai-Hulud a compromis 25K+ repos en 2025. Les outils existants detectent, mais n'aident pas a repondre.

MUAD'DIB detecte ET guide la reponse.

| Feature | MUAD'DIB | Socket | Snyk |
|---------|----------|--------|------|
| Detection IOCs | Oui | Oui | Oui |
| Analyse AST | Oui | Oui | Non |
| Analyse Dataflow | Oui | Non | Non |
| Detection Typosquatting | Oui | Oui | Non |
| Playbooks reponse | Oui | Non | Non |
| Score de risque | Oui | Oui | Oui |
| SARIF / GitHub Security | Oui | Oui | Oui |
| MITRE ATT&CK mapping | Oui | Non | Non |
| Webhook Discord/Slack | Oui | Non | Non |
| Extension VS Code | Oui | Oui | Oui |
| Mode daemon | Oui | Non | Non |
| 100% Open Source | Oui | Non | Non |

---

## Installation

### npm (recommande)
```bash
npm install -g muaddib-scanner
```

### Depuis les sources
```bash
git clone https://github.com/DNSZLSK/muad-dib.git
cd muad-dib
npm install
```

---

## Utilisation

### Scan basique
```bash
muaddib scan .
muaddib scan /chemin/vers/projet
```

### Score de risque

Chaque scan affiche un score de risque 0-100 :
```
[SCORE] 58/100 [███████████░░░░░░░░░] HIGH
```

### Mode explain (details complets)
```bash
muaddib scan . --explain
```

Affiche pour chaque detection :
- Rule ID
- MITRE ATT&CK technique
- References (articles, CVEs)
- Playbook de reponse

### Export
```bash
muaddib scan . --json > results.json     # JSON
muaddib scan . --html rapport.html       # HTML
muaddib scan . --sarif results.sarif     # SARIF (GitHub Security)
```

### Seuil de severite
```bash
muaddib scan . --fail-on critical  # Fail seulement sur CRITICAL
muaddib scan . --fail-on high      # Fail sur HIGH et CRITICAL (defaut)
muaddib scan . --fail-on medium    # Fail sur MEDIUM, HIGH, CRITICAL
```

### Webhook Discord/Slack
```bash
muaddib scan . --webhook "https://discord.com/api/webhooks/..."
```

Envoie une alerte avec le score et les menaces sur Discord ou Slack.

### Surveillance temps reel
```bash
muaddib watch .
```

### Mode daemon
```bash
muaddib daemon
muaddib daemon --webhook "https://discord.com/api/webhooks/..."
```

Surveille automatiquement tous les `npm install` et scanne les nouveaux packages.

### Mise a jour des IOCs
```bash
muaddib update
```

---

## Features

### Detection typosquatting

MUAD'DIB detecte les packages dont le nom ressemble a un package populaire :
```
[HIGH] Package "lodahs" ressemble a "lodash" (swapped_chars). Possible typosquatting.
```

### Analyse dataflow

Detecte quand du code lit des credentials ET les envoie sur le reseau :
```
[CRITICAL] Flux suspect: lecture credentials (readFileSync, GITHUB_TOKEN) + envoi reseau (fetch)
```

### Attaques detectees

| Campagne | Packages | Status |
|----------|----------|--------|
| Shai-Hulud v1 | @ctrl/tinycolor, ng2-file-upload | Detecte |
| Shai-Hulud v2 | @asyncapi/specs, posthog-node, kill-port | Detecte |
| Shai-Hulud v3 | @vietmoney/react-big-calendar | Detecte |
| event-stream (2018) | flatmap-stream, event-stream | Detecte |
| eslint-scope (2018) | eslint-scope | Detecte |
| Protestware | node-ipc, colors, faker | Detecte |
| Typosquats | crossenv, mongose, babelcli | Detecte |

### Techniques detectees

| Technique | MITRE | Detection |
|-----------|-------|-----------|
| Vol credentials (.npmrc, .ssh) | T1552.001 | AST |
| Exfiltration env vars | T1552.001 | AST |
| Execution code distant | T1105 | Pattern |
| Reverse shell | T1059.004 | Pattern |
| Dead man's switch | T1485 | Pattern |
| Code obfusque | T1027 | Heuristiques |
| Typosquatting | T1195.002 | Levenshtein |
| Supply chain compromise | T1195.002 | IOC matching |

---

## VS Code

L'extension VS Code scanne automatiquement vos projets npm.

### Installation

Le dossier `vscode-extension/` contient l'extension. Pour tester :

1. Ouvrir le dossier `vscode-extension` dans VS Code
2. Appuyer sur F5
3. Dans la nouvelle fenetre, ouvrir un projet npm

### Commandes

- `MUAD'DIB: Scan Project` - Scanner tout le projet
- `MUAD'DIB: Scan Current File` - Scanner le fichier actuel

### Configuration

- `muaddib.autoScan` - Scanner automatiquement a l'ouverture (defaut: true)
- `muaddib.webhookUrl` - URL webhook Discord/Slack
- `muaddib.failLevel` - Niveau d'alerte (critical/high/medium/low)

---

## Integration CI/CD

### GitHub Actions
```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm install -g muaddib-scanner
      - run: muaddib scan . --sarif results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

Les alertes apparaissent dans Security > Code scanning alerts.

---

## Discord

Rejoignez le serveur Discord pour :
- Recevoir les alertes de scan
- Partager des IOCs
- Contribuer au projet

---

## Architecture
```
MUAD'DIB Scanner
|
+-- IOC Match (YAML DB)
+-- AST Parse (acorn)
+-- Pattern Matching (shell, scripts)
+-- Typosquat Detection (Levenshtein)
|
v
Dataflow Analysis (credential read -> network send)
|
v
Threat Enrichment (rules, MITRE ATT&CK, playbooks)
|
v
Output (CLI, JSON, HTML, SARIF, Webhook)
```

---

## Contribuer

### Ajouter des IOCs

Editez les fichiers YAML dans `iocs/` :
```yaml
- id: NEW-MALWARE-001
  name: "malicious-package"
  version: "*"
  severity: critical
  confidence: high
  source: community
  description: "Description de la menace"
  references:
    - https://example.com/article
  mitre: T1195.002
```

### Developper
```bash
git clone https://github.com/DNSZLSK/muad-dib.git
cd muad-dib
npm install
npm test
```

---

## Documentation

- [Threat Model](docs/threat-model.md) - Ce que MUAD'DIB detecte et ne detecte pas
- [IOCs YAML](iocs/) - Base de donnees des menaces

---

## Licence

MIT

---

<p align="center">
  <strong>The spice must flow. The worms must die.</strong>
</p>