const { scanPackageJson } = require('./scanner/package.js');
const { scanShellScripts } = require('./scanner/shell.js');
const { analyzeAST } = require('./scanner/ast.js');
const { detectObfuscation } = require('./scanner/obfuscation.js');
const { scanDependencies } = require('./scanner/dependencies.js');
const { scanHashes } = require('./scanner/hash.js');
const { analyzeDataFlow } = require('./scanner/dataflow.js');
const { getPlaybook } = require('./response/playbooks.js');
const { getRule } = require('./rules/index.js');
const { saveReport } = require('./report.js');
const { saveSARIF } = require('./sarif.js');
const { scanTyposquatting } = require('./scanner/typosquat.js');

async function run(targetPath, options = {}) {
  const threats = [];

  const packageThreats = await scanPackageJson(targetPath);
  threats.push(...packageThreats);

  const shellThreats = await scanShellScripts(targetPath);
  threats.push(...shellThreats);

  const astThreats = await analyzeAST(targetPath);
  threats.push(...astThreats);

  const obfuscationThreats = detectObfuscation(targetPath);
  threats.push(...obfuscationThreats);

  const dependencyThreats = await scanDependencies(targetPath);
  threats.push(...dependencyThreats);

  const hashThreats = await scanHashes(targetPath);
  threats.push(...hashThreats);

  const dataflowThreats = await analyzeDataFlow(targetPath);
  threats.push(...dataflowThreats);

  // Scan typosquatting
  const typosquatThreats = await scanTyposquatting(targetPath);
  threats.push(...typosquatThreats);

  // Enrichir chaque menace avec les regles
  const enrichedThreats = threats.map(t => {
    const rule = getRule(t.type);
    return {
      ...t,
      rule_id: rule.id,
      rule_name: rule.name,
      confidence: rule.confidence,
      references: rule.references,
      mitre: rule.mitre,
      playbook: getPlaybook(t.type)
    };
  });

// Calculer le score de risque (0-100)
  const criticalCount = threats.filter(t => t.severity === 'CRITICAL').length;
  const highCount = threats.filter(t => t.severity === 'HIGH').length;
  const mediumCount = threats.filter(t => t.severity === 'MEDIUM').length;
  
  let riskScore = 0;
  riskScore += criticalCount * 25;  // CRITICAL = 25 points
  riskScore += highCount * 10;       // HIGH = 10 points
  riskScore += mediumCount * 3;      // MEDIUM = 3 points
  riskScore = Math.min(100, riskScore); // Cap a 100

  const riskLevel = riskScore >= 75 ? 'CRITICAL' 
                  : riskScore >= 50 ? 'HIGH'
                  : riskScore >= 25 ? 'MEDIUM'
                  : riskScore > 0 ? 'LOW'
                  : 'SAFE';

  const result = {
    target: targetPath,
    timestamp: new Date().toISOString(),
    threats: enrichedThreats,
    summary: {
      total: threats.length,
      critical: criticalCount,
      high: highCount,
      medium: mediumCount,
      riskScore: riskScore,
      riskLevel: riskLevel
    }
  };

  // Sortie JSON
  if (options.json) {
    console.log(JSON.stringify(result, null, 2));
  }
  // Sortie HTML
  else if (options.html) {
    saveReport(result, options.html);
    console.log(`[OK] Rapport HTML genere: ${options.html}`);
  }
  // Sortie SARIF
  else if (options.sarif) {
    saveSARIF(result, options.sarif);
    console.log(`[OK] Rapport SARIF genere: ${options.sarif}`);
  }
  // Sortie explain
  else if (options.explain) {
    console.log(`\n[MUADDIB] Scan de ${targetPath}\n`);

    if (enrichedThreats.length === 0) {
      console.log('[OK] Aucune menace detectee.\n');
    } else {
      console.log(`[ALERTE] ${enrichedThreats.length} menace(s) detectee(s):\n`);
      enrichedThreats.forEach((t, i) => {
        console.log(`━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━`);
        console.log(`  ${i + 1}. [${t.severity}] ${t.rule_name}`);
        console.log(`     Rule ID:    ${t.rule_id}`);
        console.log(`     Fichier:    ${t.file}`);
        if (t.line) console.log(`     Ligne:      ${t.line}`);
        console.log(`     Confidence: ${t.confidence}`);
        console.log(`     Message:    ${t.message}`);
        if (t.mitre) console.log(`     MITRE:      ${t.mitre} (https://attack.mitre.org/techniques/${t.mitre.replace('.', '/')})`);
        if (t.references && t.references.length > 0) {
          console.log(`     References:`);
          t.references.forEach(ref => console.log(`       - ${ref}`));
        }
        console.log(`     Playbook:   ${t.playbook}`);
        console.log('');
      });
    }
  }
// Sortie normale
  else {
    console.log(`\n[MUADDIB] Scan de ${targetPath}\n`);

    // Afficher le score de risque
    const scoreBar = '█'.repeat(Math.floor(result.summary.riskScore / 5)) + '░'.repeat(20 - Math.floor(result.summary.riskScore / 5));
    console.log(`[SCORE] ${result.summary.riskScore}/100 [${scoreBar}] ${result.summary.riskLevel}\n`);

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

// Calculer exit code selon le niveau de fail
  const failLevel = options.failLevel || 'high';
  const severityLevels = {
    critical: ['CRITICAL'],
    high: ['CRITICAL', 'HIGH'],
    medium: ['CRITICAL', 'HIGH', 'MEDIUM'],
    low: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
  };
  
  const levelsToCheck = severityLevels[failLevel] || severityLevels.high;
  const failingThreats = threats.filter(t => levelsToCheck.includes(t.severity));
  
  return failingThreats.length;
}

module.exports = { run };