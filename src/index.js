const { scanPackageJson } = require('./scanner/package.js');
const { scanShellScripts } = require('./scanner/shell.js');
const { analyzeAST } = require('./scanner/ast.js');
const { detectObfuscation } = require('./scanner/obfuscation.js');
const { getPlaybook } = require('./response/playbooks.js');

async function run(targetPath) {
  console.log(`\n[MUADDIB] Scan de ${targetPath}\n`);
  
  const threats = [];

  // Scan package.json
  const packageThreats = await scanPackageJson(targetPath);
  threats.push(...packageThreats);

  // Scan scripts shell
  const shellThreats = await scanShellScripts(targetPath);
  threats.push(...shellThreats);

  // Analyse AST des fichiers JS
  const astThreats = await analyzeAST(targetPath);
  threats.push(...astThreats);

  // Detection d'obfuscation
  const obfuscationThreats = detectObfuscation(targetPath);
  threats.push(...obfuscationThreats);

  // Resultats
  if (threats.length === 0) {
    console.log('[OK] Aucune menace detectee.\n');
  } else {
    console.log(`[ALERTE] ${threats.length} menace(s) detectee(s):\n`);
    threats.forEach((t, i) => {
      console.log(`  ${i + 1}. [${t.severity}] ${t.type}`);
      console.log(`     ${t.message}`);
      console.log(`     Fichier: ${t.file}\n`);
    });

    // Playbook de reponse
    console.log('[REPONSE] Recommandations:\n');
    threats.forEach(t => {
      const playbook = getPlaybook(t.type);
      if (playbook) {
        console.log(`  -> ${playbook}\n`);
      }
    });
  }
}

module.exports = { run };