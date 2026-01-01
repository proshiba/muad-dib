#!/usr/bin/env node

const { run } = require('../src/index.js');

const args = process.argv.slice(2);
const command = args[0];
const options = args.slice(1);

let target = '.';
let jsonOutput = false;

for (let i = 0; i < options.length; i++) {
  if (options[i] === '--json') {
    jsonOutput = true;
  } else if (!options[i].startsWith('-')) {
    target = options[i];
  }
}

if (!command) {
  console.log(`
  MUAD'DIB - Chasseur de vers npm
  
  Usage:
    muaddib scan [path] [--json]    Analyse un projet
    muaddib help                    Affiche l'aide
  
  Options:
    --json    Sortie au format JSON
  `);
  process.exit(0);
}

if (command === 'scan') {
  run(target, { json: jsonOutput }).then(exitCode => {
    process.exit(exitCode);
  });
} else if (command === 'help') {
  console.log('muaddib scan [path] [--json] - Analyse un projet npm');
} else {
  console.log(`Commande inconnue: ${command}`);
  process.exit(1);
}