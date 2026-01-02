const fs = require('fs');
const path = require('path');
const acorn = require('acorn');
const walk = require('acorn-walk');

const EXCLUDED_FILES = [
  'src/scanner/ast.js',
  'src/scanner/shell.js',
  'src/scanner/package.js',
  'src/ioc/feeds.js',
  'src/response/playbooks.js'
];

const EXCLUDED_DIRS = ['test', 'tests', 'node_modules', '.git', 'src'];

const DANGEROUS_CALLS = [
  'eval',
  'Function',
  'exec',
  'execSync',
  'spawn',
  'spawnSync'
];

const SENSITIVE_STRINGS = [
  '.npmrc',
  '.ssh',
  'GITHUB_TOKEN',
  'NPM_TOKEN',
  'AWS_SECRET',
  'api.github.com',
  'Shai-Hulud',
  'The Second Coming',
  'Goldox-T3chs'
];

async function analyzeAST(targetPath) {
  const threats = [];
  const files = findJsFiles(targetPath);

  for (const file of files) {
    const relativePath = path.relative(targetPath, file).replace(/\\/g, '/');
    
    if (EXCLUDED_FILES.includes(relativePath)) {
      continue;
    }
    
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
    // Fichier non parseable, peut etre obfusque
    if (content.length > 1000 && content.split('\n').length < 10) {
      threats.push({
        type: 'possible_obfuscation',
        severity: 'MEDIUM',
        message: 'Fichier difficilement parseable, possiblement obfusque.',
        file: path.relative(basePath, filePath)
      });
    }
    return threats;
  }

  // Analyse des appels de fonction
  walk.simple(ast, {
    CallExpression(node) {
      const callName = getCallName(node);
      
      if (DANGEROUS_CALLS.includes(callName)) {
        threats.push({
          type: 'dangerous_call_' + callName.toLowerCase(),
          severity: callName === 'eval' ? 'HIGH' : 'MEDIUM',
          message: `Appel dangereux "${callName}" detecte.`,
          file: path.relative(basePath, filePath)
        });
      }
    },

    NewExpression(node) {
      if (node.callee.type === 'Identifier' && node.callee.name === 'Function') {
        threats.push({
          type: 'dangerous_call_function',
          severity: 'HIGH',
          message: 'Appel dangereux "new Function()" detecte.',
          file: path.relative(basePath, filePath)
        });
      }
    },

    Literal(node) {
      if (typeof node.value === 'string') {
        for (const sensitive of SENSITIVE_STRINGS) {
          if (node.value.includes(sensitive)) {
            threats.push({
              type: 'sensitive_string',
              severity: 'HIGH',
              message: `Reference a "${sensitive}" detectee.`,
              file: path.relative(basePath, filePath)
            });
          }
        }
      }
    },

    MemberExpression(node) {
      // Detecte process.env.XXX
      if (
        node.object?.object?.name === 'process' &&
        node.object?.property?.name === 'env'
      ) {
        const envVar = node.property?.name;
        if (envVar && SENSITIVE_STRINGS.some(s => envVar.includes(s.replace('.', '')))) {
          threats.push({
            type: 'env_access',
            severity: 'HIGH',
            message: `Acces a variable sensible process.env.${envVar}.`,
            file: path.relative(basePath, filePath)
          });
        }
      }
    }
  });

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

function findJsFiles(dir) {
  const results = [];
  
  if (!fs.existsSync(dir)) return results;
  
  const items = fs.readdirSync(dir);
  
  for (const item of items) {
    if (EXCLUDED_DIRS.includes(item)) continue;
    
    const fullPath = path.join(dir, item);
    const stat = fs.statSync(fullPath);
    
    if (stat.isDirectory()) {
      results.push(...findJsFiles(fullPath));
    } else if (item.endsWith('.js')) {
      results.push(fullPath);
    }
  }
  
  return results;
}

module.exports = { analyzeAST };