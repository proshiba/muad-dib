const fs = require('fs');
const path = require('path');

function detectObfuscation(targetPath) {
  const threats = [];
  const files = findJsFiles(targetPath);

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf8');
    const relativePath = path.relative(targetPath, file);

    const signals = [];
    let score = 0;

    // 1. Ratio code sur une seule ligne
    const lines = content.split('\n').filter(l => l.trim());
    const longLines = lines.filter(l => l.length > 500);
    if (lines.length > 0 && longLines.length / lines.length > 0.3) {
      score += 25;
      signals.push('long_single_lines');
    }

    // 2. Hex escapes massifs
    const hexMatches = content.match(/\\x[0-9a-fA-F]{2}/g) || [];
    if (hexMatches.length > 20) {
      score += 25;
      signals.push('hex_escapes');
    }

    // 3. Unicode escapes massifs
    const unicodeMatches = content.match(/\\u[0-9a-fA-F]{4}/g) || [];
    if (unicodeMatches.length > 20) {
      score += 20;
      signals.push('unicode_escapes');
    }

    // 4. Variables style obfuscateur (_0x, _0xabc)
    const obfuscatedVars = content.match(/\b_0x[a-f0-9]+\b/gi) || [];
    if (obfuscatedVars.length > 5) {
      score += 30;
      signals.push('obfuscated_variables');
    }

    // 5. String arrays suspects
    if (/var\s+\w+\s*=\s*\[(['"][^'"]{0,50}['"],?\s*){10,}\]/.test(content)) {
      score += 25;
      signals.push('string_array');
    }

    // 6. atob/btoa avec eval
    if (/atob\s*\(/.test(content) && /(eval|Function)\s*\(/.test(content)) {
      score += 30;
      signals.push('base64_eval');
    }

    if (score >= 40) {
      threats.push({
        type: 'obfuscation_detected',
        severity: score >= 70 ? 'CRITICAL' : 'HIGH',
        message: `Code obfusque (score: ${score}). Signaux: ${signals.join(', ')}`,
        file: relativePath
      });
    }
  }

  return threats;
}

const EXCLUDED_DIRS = [
  'test',
  'node_modules',
  '.git',
  'src'
];

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

module.exports = { detectObfuscation };