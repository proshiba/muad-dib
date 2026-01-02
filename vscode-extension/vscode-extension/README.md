# MUAD'DIB Security Scanner for VS Code

Detecte les attaques supply chain npm directement dans VS Code.

## Features

- Scan automatique a l'ouverture d'un projet npm
- Detection des packages malveillants (Shai-Hulud, event-stream, etc.)
- Detection du typosquatting
- Analyse AST et dataflow
- Score de risque 0-100
- Alertes Discord/Slack
- Diagnostics inline dans l'editeur

## Installation

1. Installer l'extension depuis VS Code Marketplace
2. Ouvrir un projet npm
3. Le scan se lance automatiquement

## Commandes

- `MUAD'DIB: Scan Project` — Scanner tout le projet
- `MUAD'DIB: Scan Current File` — Scanner le fichier actuel

## Configuration

- `muaddib.autoScan` — Scanner automatiquement (defaut: true)
- `muaddib.webhookUrl` — URL webhook Discord/Slack
- `muaddib.failLevel` — Niveau d'alerte (critical/high/medium/low)

## Prerequis

- Node.js >= 18
- muaddib-scanner installe globalement : `npm install -g muaddib-scanner`
```

Sauvegarde.

Ouvre `vscode-extension/.vscodeignore` et mets :
```
.git
node_modules
*.md