const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');

const EXCLUDED_DIRS = ['test', 'tests', 'node_modules', '.git', 'src', 'vscode-extension'];

async function analyzeDataFlow(targetPath) {
  const threats = [];
  const files = findJsFiles(targetPath);

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');
    const fileThreats = analyzeFile(content, file, targetPath);
    threats.push(...fileThreats);
  }

  return threats;
}

function analyzeFile(content, filePath, basePath) {
  const threats = [];
  let ast;

  try {
    ast = acorn.parse(content, {
      ecmaVersion: 2022,
      sourceType: 'module',
      allowHashBang: true
    });
  } catch (e) {
    return threats;
  }

  const sources = [];  // Ou les donnees sensibles sont lues
  const sinks = [];    // Ou les donnees sont envoyees

  walk.simple(ast, {
    // Detecte les lectures de fichiers sensibles
    CallExpression(node) {
      const callName = getCallName(node);
      
      // fs.readFileSync, fs.readFile
      if (callName === 'readFileSync' || callName === 'readFile') {
        const arg = node.arguments[0];
        if (arg && isCredentialPath(arg, content)) {
          sources.push({
            type: 'credential_read',
            name: callName,
            line: node.loc?.start?.line
          });
        }
      }

      // Detecte les envois reseau
      if (callName === 'request' || callName === 'fetch' || callName === 'post' || callName === 'get') {
        sinks.push({
          type: 'network_send',
          name: callName,
          line: node.loc?.start?.line
        });
      }

      // exec avec curl/wget
      if (callName === 'exec' || callName === 'execSync') {
        const arg = node.arguments[0];
        if (arg && arg.type === 'Literal' && typeof arg.value === 'string') {
          if (arg.value.includes('curl') || arg.value.includes('wget')) {
            sinks.push({
              type: 'exec_network',
              name: callName,
              line: node.loc?.start?.line
            });
          }
        }
      }
    },

    // Detecte les acces process.env sensibles
    MemberExpression(node) {
      if (
        node.object?.object?.name === 'process' &&
        node.object?.property?.name === 'env'
      ) {
        const envVar = node.property?.name || '';
        if (isSensitiveEnv(envVar)) {
          sources.push({
            type: 'env_read',
            name: envVar,
            line: node.loc?.start?.line
          });
        }
      }
    }
  });

  // Si on a des sources ET des sinks = flux suspect
  if (sources.length > 0 && sinks.length > 0) {
    threats.push({
      type: 'suspicious_dataflow',
      severity: 'CRITICAL',
      message: `Flux suspect: lecture credentials (${sources.map(s => s.name).join(', ')}) + envoi reseau (${sinks.map(s => s.name).join(', ')})`,
      file: path.relative(basePath, filePath)
    });
  }

  return threats;
}

function getCallName(node) {
  if (node.callee.type === 'Identifier') {
    return node.callee.name;
  }
  if (node.callee.type === 'MemberExpression' && node.callee.property) {
    return node.callee.property.name;
  }
  return '';
}

function isCredentialPath(arg, content) {
  if (arg.type === 'Literal' && typeof arg.value === 'string') {
    const val = arg.value.toLowerCase();
    return val.includes('.npmrc') || 
           val.includes('.ssh') || 
           val.includes('.aws') ||
           val.includes('.gitconfig') ||
           val.includes('.env');
  }
  // Verifie aussi les templates strings et concatenations
  if (arg.type === 'TemplateLiteral' || arg.type === 'BinaryExpression') {
    return content.includes('.npmrc') || 
           content.includes('.ssh') ||
           content.includes('.aws');
  }
  return false;
}

function isSensitiveEnv(name) {
  const sensitive = ['TOKEN', 'SECRET', 'KEY', 'PASSWORD', 'CREDENTIAL', 'AUTH', 'NPM', 'GITHUB', 'AWS', 'AZURE', 'GCP'];
  return sensitive.some(s => name.toUpperCase().includes(s));
}

function findJsFiles(dir, results = []) {
  if (!fs.existsSync(dir)) return results;

  const items = fs.readdirSync(dir);

  for (const item of items) {
    if (EXCLUDED_DIRS.includes(item)) continue;

    const fullPath = path.join(dir, item);
    
    try {
      const stat = fs.statSync(fullPath);
      
      if (stat.isDirectory()) {
        findJsFiles(fullPath, results);
      } else if (item.endsWith('.js')) {
        results.push(fullPath);
      }
    } catch (e) {}
  }

  return results;
}

module.exports = { analyzeDataFlow };