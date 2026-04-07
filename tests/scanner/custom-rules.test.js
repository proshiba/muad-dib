'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const {
  test, assert, assertIncludes, assertNotIncludes,
  asyncTest, runScanDirect
} = require('../test-utils');
const {
  scanCustomRules,
  loadCustomRulesFromDir,
  resolveCustomRulesDirs,
  validateCustomRule
} = require('../../src/scanner/custom-rules');
const { clearCustomRules } = require('../../src/rules/index');

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

/** Create a temp directory with a custom rule folder inside it. */
function makeTempCustomRulesDir(rules) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-crtest-'));
  for (const [folderName, ruleJson] of Object.entries(rules)) {
    const ruleDir = path.join(base, folderName);
    fs.mkdirSync(ruleDir, { recursive: true });
    fs.writeFileSync(path.join(ruleDir, 'rule.json'), JSON.stringify(ruleJson), 'utf8');
  }
  return base;
}

/** Create a temp scan target directory with given files. */
function makeTempTarget(files) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-target-'));
  for (const [name, content] of Object.entries(files)) {
    const full = path.join(base, name);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content, 'utf8');
  }
  return base;
}

function cleanup(...dirs) {
  for (const d of dirs) {
    try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ }
  }
}

// ─────────────────────────────────────────────
// Test suite
// ─────────────────────────────────────────────

async function runCustomRulesTests() {
  console.log('\n=== CUSTOM RULES TESTS ===\n');

  // ── validateCustomRule ─────────────────────

  test('custom-rules: validateCustomRule accepts valid rule', () => {
    const raw = {
      id: 'CUSTOM-001',
      name: 'Test Rule',
      severity: 'HIGH',
      confidence: 'high',
      description: 'Test description',
      patterns: [{ regex: 'evil_function\\(', flags: 'i', message: 'Evil function call' }]
    };
    const { rule, errors } = validateCustomRule('myrule', raw);
    assert(errors.length === 0, `Expected no errors, got: ${errors.join(', ')}`);
    assert(rule !== null, 'Expected rule to be non-null');
    assert(rule.typeKey === 'custom_myrule', `Expected typeKey custom_myrule, got ${rule.typeKey}`);
    assert(rule.severity === 'HIGH', 'Severity should be HIGH');
    assert(rule.patterns.length === 1, 'Expected 1 pattern');
  });

  test('custom-rules: validateCustomRule rejects missing id', () => {
    const raw = {
      name: 'Test Rule', severity: 'HIGH', confidence: 'high',
      description: 'desc', patterns: [{ regex: 'x' }]
    };
    const { rule, errors } = validateCustomRule('folder', raw);
    assert(rule === null, 'Expected null rule');
    assert(errors.some(e => e.includes('"id"')), `Expected error about "id", got: ${errors}`);
  });

  test('custom-rules: validateCustomRule rejects invalid severity', () => {
    const raw = {
      id: 'C-001', name: 'Test', severity: 'EXTREME', confidence: 'high',
      description: 'desc', patterns: [{ regex: 'x' }]
    };
    const { rule, errors } = validateCustomRule('folder', raw);
    assert(rule === null, 'Expected null rule');
    assert(errors.some(e => e.includes('severity')), `Expected error about severity: ${errors}`);
  });

  test('custom-rules: validateCustomRule rejects invalid confidence', () => {
    const raw = {
      id: 'C-001', name: 'Test', severity: 'HIGH', confidence: 'extreme',
      description: 'desc', patterns: [{ regex: 'x' }]
    };
    const { rule, errors } = validateCustomRule('folder', raw);
    assert(rule === null, 'Expected null rule');
    assert(errors.some(e => e.includes('confidence')), `Expected error about confidence: ${errors}`);
  });

  test('custom-rules: validateCustomRule rejects invalid regex', () => {
    const raw = {
      id: 'C-001', name: 'Test', severity: 'HIGH', confidence: 'high',
      description: 'desc', patterns: [{ regex: '(unclosed' }]
    };
    const { rule, errors } = validateCustomRule('folder', raw);
    assert(rule === null, 'Expected null rule');
    assert(errors.some(e => e.includes('regex')), `Expected error about regex: ${errors}`);
  });

  test('custom-rules: validateCustomRule rejects invalid flags', () => {
    const raw = {
      id: 'C-001', name: 'Test', severity: 'HIGH', confidence: 'high',
      description: 'desc', patterns: [{ regex: 'x', flags: 'z' }]
    };
    const { rule, errors } = validateCustomRule('folder', raw);
    assert(rule === null, 'Expected null rule');
    assert(errors.some(e => e.includes('flags')), `Expected error about flags: ${errors}`);
  });

  test('custom-rules: validateCustomRule blocks prototype pollution keys', () => {
    // Use JSON.parse to simulate how rule.json is loaded — __proto__ appears as own key
    const raw = JSON.parse('{"__proto__":{"bad":true},"id":"X","name":"X","severity":"HIGH","confidence":"high","description":"x","patterns":[{"regex":"x"}]}');
    const { rule, errors } = validateCustomRule('folder', raw);
    assert(rule === null, 'Expected null rule for __proto__ key');
    assert(errors.some(e => e.includes('Forbidden')), `Expected forbidden key error: ${errors}`);
  });

  test('custom-rules: validateCustomRule accepts optional fileExtensions', () => {
    const raw = {
      id: 'C-001', name: 'Test', severity: 'HIGH', confidence: 'high',
      description: 'desc', patterns: [{ regex: 'x' }],
      fileExtensions: ['.js', '.py']
    };
    const { rule, errors } = validateCustomRule('folder', raw);
    assert(errors.length === 0, `No errors expected: ${errors}`);
    assert(Array.isArray(rule.fileExtensions), 'fileExtensions should be an array');
    assert(rule.fileExtensions.includes('.js'), 'Should include .js');
  });

  // ── loadCustomRulesFromDir ─────────────────

  test('custom-rules: loadCustomRulesFromDir returns empty for non-existent dir', () => {
    const { rules, warnings } = loadCustomRulesFromDir('/non/existent/path');
    assert(rules.length === 0, 'Expected no rules');
    assert(warnings.length === 0, 'Expected no warnings for missing dir');
  });

  test('custom-rules: loadCustomRulesFromDir loads a valid rule', () => {
    const base = makeTempCustomRulesDir({
      myrule: {
        id: 'CUSTOM-001', name: 'My Rule', severity: 'CRITICAL', confidence: 'high',
        description: 'Test', patterns: [{ regex: 'dangerousCall\\(', message: 'Danger' }]
      }
    });
    try {
      const { rules, warnings } = loadCustomRulesFromDir(base);
      assert(rules.length === 1, `Expected 1 rule, got ${rules.length}`);
      assert(rules[0].typeKey === 'custom_myrule', `Wrong typeKey: ${rules[0].typeKey}`);
      assert(warnings.length === 0, `Unexpected warnings: ${warnings}`);
    } finally {
      cleanup(base);
    }
  });

  test('custom-rules: loadCustomRulesFromDir warns on missing rule.json', () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-crtest-'));
    fs.mkdirSync(path.join(base, 'emptyrule'), { recursive: true });
    try {
      const { rules, warnings } = loadCustomRulesFromDir(base);
      assert(rules.length === 0, 'Expected no rules');
      assert(warnings.some(w => w.includes('missing rule.json')), `Expected warning about missing rule.json: ${warnings}`);
    } finally {
      cleanup(base);
    }
  });

  test('custom-rules: loadCustomRulesFromDir warns on invalid JSON', () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-crtest-'));
    const ruleDir = path.join(base, 'badrule');
    fs.mkdirSync(ruleDir, { recursive: true });
    fs.writeFileSync(path.join(ruleDir, 'rule.json'), '{not valid json', 'utf8');
    try {
      const { rules, warnings } = loadCustomRulesFromDir(base);
      assert(rules.length === 0, 'Expected no rules');
      assert(warnings.some(w => w.includes('parse error')), `Expected parse error warning: ${warnings}`);
    } finally {
      cleanup(base);
    }
  });

  test('custom-rules: loadCustomRulesFromDir skips files (not dirs)', () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), 'muaddib-crtest-'));
    fs.writeFileSync(path.join(base, 'not-a-folder.json'), '{}', 'utf8');
    try {
      const { rules } = loadCustomRulesFromDir(base);
      assert(rules.length === 0, 'Files at top level should be skipped');
    } finally {
      cleanup(base);
    }
  });

  // ── scanCustomRules ────────────────────────

  test('custom-rules: scanCustomRules detects pattern in target file', () => {
    const rulesDir = makeTempCustomRulesDir({
      testrule: {
        id: 'CUSTOM-TEST-001', name: 'Test Detection', severity: 'HIGH', confidence: 'high',
        description: 'Detects evil call', patterns: [{ regex: 'evilFunction\\(', message: 'Evil function detected' }]
      }
    });
    const target = makeTempTarget({ 'index.js': 'const x = evilFunction(data);' });
    const warnings = [];
    try {
      const threats = scanCustomRules(target, { customRulesDir: rulesDir }, warnings);
      assert(threats.length >= 1, `Expected at least 1 threat, got ${threats.length}`);
      assert(threats[0].type === 'custom_testrule', `Wrong type: ${threats[0].type}`);
      assert(threats[0].severity === 'HIGH', `Wrong severity: ${threats[0].severity}`);
      assertIncludes(threats[0].message, 'Evil function detected', 'Message should contain pattern message');
      assert(threats[0].line >= 1, `Expected line >= 1, got ${threats[0].line}`);
      assert(typeof threats[0].matchedText === 'string', `Expected matchedText to be a string, got ${typeof threats[0].matchedText}`);
      assertIncludes(threats[0].matchedText, 'evilFunction(', 'matchedText should contain the matched string');
    } finally {
      cleanup(rulesDir, target);
      clearCustomRules();
    }
  });

  test('custom-rules: scanCustomRules does not fire on clean file', () => {
    const rulesDir = makeTempCustomRulesDir({
      testrule: {
        id: 'CUSTOM-TEST-002', name: 'Test Detection', severity: 'MEDIUM', confidence: 'medium',
        description: 'Detects evil call', patterns: [{ regex: 'verySuspiciousPattern123' }]
      }
    });
    const target = makeTempTarget({ 'index.js': 'console.log("hello world");' });
    const warnings = [];
    try {
      const threats = scanCustomRules(target, { customRulesDir: rulesDir }, warnings);
      assert(threats.length === 0, `Expected 0 threats, got ${threats.length}`);
    } finally {
      cleanup(rulesDir, target);
      clearCustomRules();
    }
  });

  test('custom-rules: scanCustomRules respects fileExtensions filter', () => {
    const rulesDir = makeTempCustomRulesDir({
      jsonly: {
        id: 'CUSTOM-TEST-003', name: 'JS Only', severity: 'HIGH', confidence: 'high',
        description: 'JS-only pattern', patterns: [{ regex: 'dangerousCode' }],
        fileExtensions: ['.js']
      }
    });
    const target = makeTempTarget({
      'index.js': 'dangerousCode();',
      'index.py': 'dangerousCode()'
    });
    const warnings = [];
    try {
      const threats = scanCustomRules(target, { customRulesDir: rulesDir }, warnings);
      // Should detect in .js but not in .py
      const jsThreats = threats.filter(t => t.file.endsWith('.js'));
      const pyThreats = threats.filter(t => t.file.endsWith('.py'));
      assert(jsThreats.length >= 1, 'Should detect in .js file');
      assert(pyThreats.length === 0, 'Should not detect in .py file (filtered out)');
    } finally {
      cleanup(rulesDir, target);
      clearCustomRules();
    }
  });

  test('custom-rules: scanCustomRules returns empty when no rules dir exists', () => {
    const target = makeTempTarget({ 'index.js': 'console.log("clean");' });
    const warnings = [];
    try {
      const threats = scanCustomRules(target, { customRulesDir: '/non/existent/rules' }, warnings);
      assert(threats.length === 0, 'Should return no threats if rules dir is missing');
    } finally {
      cleanup(target);
      clearCustomRules();
    }
  });

  test('custom-rules: scanCustomRules returns empty when no customRulesDir and cwd === targetPath', () => {
    // When no explicit dir and cwd equals targetPath, no CWD-based rules should be loaded
    const target = makeTempTarget({ 'index.js': 'bad_pattern_xyz();' });
    const savedCwd = process.cwd();
    process.chdir(target);
    const warnings = [];
    try {
      const threats = scanCustomRules(target, {}, warnings);
      // There should be no threats from cwd rules (cwd === targetPath → skipped)
      const customThreats = threats.filter(t => t.type && t.type.startsWith('custom_'));
      assert(customThreats.length === 0, 'Should not load custom rules from targetPath');
    } finally {
      process.chdir(savedCwd);
      cleanup(target);
      clearCustomRules();
    }
  });

  // ── resolveCustomRulesDirs ─────────────────

  test('custom-rules: resolveCustomRulesDirs uses explicit dir when provided', () => {
    const dirs = resolveCustomRulesDirs('/some/target', '/my/custom/rules');
    assert(dirs.length === 1, 'Expected exactly 1 dir');
    assert(dirs[0] === '/my/custom/rules', `Wrong dir: ${dirs[0]}`);
  });

  test('custom-rules: resolveCustomRulesDirs excludes cwd when cwd equals targetPath', () => {
    const cwd = process.cwd();
    const dirs = resolveCustomRulesDirs(cwd, null);
    const cwdRules = path.join(cwd, 'custom_rules');
    assert(!dirs.includes(cwdRules), 'Should not include cwd/custom_rules when cwd === targetPath');
  });

  test('custom-rules: resolveCustomRulesDirs includes home dir rules', () => {
    const dirs = resolveCustomRulesDirs('/some/other/target', null);
    const homeRules = path.join(os.homedir(), '.muaddib', 'custom_rules');
    assert(dirs.includes(homeRules), 'Should include ~/.muaddib/custom_rules');
  });

  // ── integration: end-to-end via run() ──────

  asyncTest('custom-rules: integration scan detects custom rule threat', async () => {
    const rulesDir = makeTempCustomRulesDir({
      integration_rule: {
        id: 'CUSTOM-INT-001', name: 'Integration Test Rule', severity: 'CRITICAL',
        confidence: 'high', description: 'Integration test pattern',
        patterns: [{ regex: '__INTEGRATION_TEST_EVIL_MARKER__', message: 'Integration marker found' }]
      }
    });
    const target = makeTempTarget({
      'package.json': JSON.stringify({ name: 'test-pkg', version: '1.0.0' }),
      'index.js': 'const x = "__INTEGRATION_TEST_EVIL_MARKER__";'
    });
    try {
      const result = await runScanDirect(target, { customRulesDir: rulesDir, _capture: true });
      assert(result && Array.isArray(result.threats), 'Expected threats array');
      const customThreat = result.threats.find(t => t.type === 'custom_integration_rule');
      assert(customThreat, 'Expected custom rule threat in result');
      assert(customThreat.rule_id === 'CUSTOM-INT-001', `Expected rule_id CUSTOM-INT-001, got ${customThreat.rule_id}`);
    } finally {
      cleanup(rulesDir, target);
      clearCustomRules();
    }
  });

  asyncTest('custom-rules: integration scan with no custom rules dir is clean', async () => {
    const target = makeTempTarget({
      'package.json': JSON.stringify({ name: 'test-pkg', version: '1.0.0' }),
      'index.js': 'console.log("hello");'
    });
    try {
      const result = await runScanDirect(target, { customRulesDir: '/non/existent', _capture: true });
      assert(result && Array.isArray(result.threats), 'Expected threats array');
      const customThreats = result.threats.filter(t => t.type && t.type.startsWith('custom_'));
      assert(customThreats.length === 0, 'Expected no custom threats for clean file');
    } finally {
      cleanup(target);
      clearCustomRules();
    }
  });
}

module.exports = { runCustomRulesTests };
