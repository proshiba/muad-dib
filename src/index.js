const { scanPackageJson } = require('./scanner/package.js');
const { scanShellScripts } = require('./scanner/shell.js');
const { analyzeAST } = require('./scanner/ast.js');
const { detectObfuscation } = require('./scanner/obfuscation.js');
const { scanDependencies } = require('./scanner/dependencies.js');
const { getPlaybook } = require('./response/playbooks.js');

async function run(targetPath, options = {}) {
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

  // Scan des dependances node_modules
  const dependencyThreats = await scanDependencies(targetPath);
  threats.push(...dependencyThreats);

  // Sortie JSON
  if (options.json) {
    const result = {
      target: targetPath,
      timestamp: new Date().toISOString(),
      threats: threats.map(t => ({
        ...t,
        playbook: getPlaybook(t.type)
      })),
      summary: {
        total: threats.length,
        critical: threats.filter(t => t.severity === 'CRITICAL').length,
        high: threats.filter(t => t.severity === 'HIGH').length,
        medium: threats.filter(t => t.severity === 'MEDIUM').length
      }
    };
    console.log(JSON.stringify(result, null, 2));
  } else {
    // Sortie normale
    console.log(`\n[MUADDIB] Scan de ${targetPath}\n`);

    if (threats.length === 0) {
      console.log('[OK] Aucune menace detectee.\n');
    } else {
      console.log(`[ALERTE] ${threats.length} menace(s) detectee(s):\n`);
      threats.forEach((t, i) => {
        console.log(`  ${i + 1}. [${t.severity}] ${t.type}`);
        console.log(`     ${t.message}`);
        console.log(`     Fichier: ${t.file}\n`);
      });

      console.log('[REPONSE] Recommandations:\n');
      threats.forEach(t => {
        const playbook = getPlaybook(t.type);
        if (playbook) {
          console.log(`  -> ${playbook}\n`);
        }
      });
    }
  }

  // Retourne le nombre de menaces critiques/high
  const critical = threats.filter(t => t.severity === 'CRITICAL' || t.severity === 'HIGH');
  return critical.length;
}

module.exports = { run };