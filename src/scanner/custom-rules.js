'use strict';

/**
 * Custom Rules Scanner
 *
 * Loads user-defined detection rules from individual subfolders under a
 * custom_rules/ directory. Each subfolder contains a rule.json file with
 * the rule definition and regex patterns. This allows adding new detections
 * without modifying the muad-dib source code.
 *
 * Directory resolution (most specific wins, all candidates searched):
 *   1. --custom-rules-dir <path>  (explicit CLI override)
 *   2. ~/.muaddib/custom_rules/   (per-user global rules)
 *   3. <cwd>/custom_rules/        (project-local, ONLY when cwd !== targetPath)
 *
 * SECURITY: Custom rules are NEVER loaded from inside the scanned package
 * (targetPath) to prevent an attacker from injecting rules that suppress
 * detections or generate false positives.
 *
 * rule.json schema:
 * {
 *   "id":          string   — rule identifier, e.g. "CUSTOM-001"
 *   "name":        string   — human-readable rule name
 *   "severity":    "CRITICAL"|"HIGH"|"MEDIUM"|"LOW"
 *   "confidence":  "high"|"medium"|"low"
 *   "description": string
 *   "references":  string[] (optional)
 *   "mitre":       string   (optional, e.g. "T1059")
 *   "patterns":    Array<{
 *     "regex":   string  — regex source (e.g. "eval\\s*\\(")
 *     "flags":   string  — optional regex flags (default "")
 *     "message": string  — optional human-readable match message
 *   }>
 *   "fileExtensions": string[] (optional — if omitted, all common text files)
 * }
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const { findFiles, debugLog } = require('../utils.js');
const { getMaxFileSize } = require('../shared/constants.js');
const { registerCustomRules } = require('../rules/index.js');

const MAX_CUSTOM_RULE_FILE_SIZE = 64 * 1024; // 64 KB
const MAX_MATCHED_TEXT_LENGTH = 200;
const MAX_CUSTOM_RULES = 100;

const VALID_SEVERITIES = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']);
const VALID_CONFIDENCES = new Set(['high', 'medium', 'low']);
const VALID_FLAGS_RE = /^[gimsuy]*$/;
const PROTO_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

// Default extensions when a rule does not specify fileExtensions
const DEFAULT_SCAN_EXTENSIONS = [
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx',
  '.py', '.rb', '.php', '.go', '.java',
  '.sh', '.bash', '.zsh',
  '.json', '.yaml', '.yml', '.toml',
  '.env', '.cfg', '.conf', '.ini'
];

/**
 * Resolve candidate directories for custom rules.
 * @param {string} targetPath - scan target (never loaded from here)
 * @param {string|null} customRulesDir - explicit override from CLI
 * @returns {string[]}
 */
function resolveCustomRulesDirs(targetPath, customRulesDir) {
  if (customRulesDir) {
    const abs = path.isAbsolute(customRulesDir)
      ? customRulesDir
      : path.resolve(customRulesDir);
    return [abs];
  }

  const candidates = [];

  // 1. Per-user global: ~/.muaddib/custom_rules
  candidates.push(path.join(os.homedir(), '.muaddib', 'custom_rules'));

  // 2. Project-local: <cwd>/custom_rules — only when cwd is not the scan target
  const cwd = process.cwd();
  if (path.resolve(cwd) !== path.resolve(targetPath)) {
    candidates.push(path.join(cwd, 'custom_rules'));
  }

  return candidates;
}

/**
 * Validate a raw rule.json object for a given folder name.
 * @param {string} folderName
 * @param {object} raw
 * @returns {{ rule: object|null, errors: string[] }}
 */
function validateCustomRule(folderName, raw) {
  const errors = [];

  // Prototype pollution check (top-level)
  for (const key of Object.keys(raw)) {
    if (PROTO_KEYS.has(key)) {
      errors.push(`Forbidden key "${key}" (prototype pollution attempt)`);
      return { rule: null, errors };
    }
  }

  const { id, name, severity, confidence, description, patterns } = raw;

  if (!id || typeof id !== 'string' || !id.trim())
    errors.push('Missing or invalid "id" field (must be a non-empty string)');
  if (!name || typeof name !== 'string' || !name.trim())
    errors.push('Missing or invalid "name" field (must be a non-empty string)');
  if (!VALID_SEVERITIES.has(severity))
    errors.push(`Invalid "severity" "${severity}" (expected CRITICAL|HIGH|MEDIUM|LOW)`);
  if (!VALID_CONFIDENCES.has(confidence))
    errors.push(`Invalid "confidence" "${confidence}" (expected high|medium|low)`);
  if (!description || typeof description !== 'string' || !description.trim())
    errors.push('Missing or invalid "description" field (must be a non-empty string)');
  if (!Array.isArray(patterns) || patterns.length === 0)
    errors.push('"patterns" must be a non-empty array');

  if (errors.length > 0) return { rule: null, errors };

  // Validate each pattern
  const compiledPatterns = [];
  for (let i = 0; i < patterns.length; i++) {
    const p = patterns[i];
    if (typeof p !== 'object' || p === null || Array.isArray(p)) {
      errors.push(`Pattern[${i}]: must be an object`);
      continue;
    }
    // Prototype pollution check (nested)
    for (const key of Object.keys(p)) {
      if (PROTO_KEYS.has(key)) {
        errors.push(`Pattern[${i}]: forbidden key "${key}"`);
        return { rule: null, errors };
      }
    }
    if (!p.regex || typeof p.regex !== 'string') {
      errors.push(`Pattern[${i}]: missing or invalid "regex" field`);
      continue;
    }
    const flags = (p.flags && typeof p.flags === 'string') ? p.flags : '';
    if (!VALID_FLAGS_RE.test(flags)) {
      errors.push(`Pattern[${i}]: invalid regex flags "${flags}" (allowed: g i m s u y)`);
      continue;
    }
    let compiled;
    try {
      compiled = new RegExp(p.regex, flags);
    } catch (e) {
      errors.push(`Pattern[${i}]: invalid regex "${p.regex}": ${e.message}`);
      continue;
    }
    const message = (p.message && typeof p.message === 'string' && p.message.trim())
      ? p.message.trim()
      : `Pattern matched in rule "${name}"`;
    compiledPatterns.push({ compiled, message, regex: p.regex, flags });
  }

  if (errors.length > 0) return { rule: null, errors };
  if (compiledPatterns.length === 0) {
    errors.push('No valid patterns found');
    return { rule: null, errors };
  }

  // Validate optional fileExtensions
  let fileExtensions = null;
  if (raw.fileExtensions !== undefined) {
    if (!Array.isArray(raw.fileExtensions)) {
      errors.push('"fileExtensions" must be an array of strings (e.g. [".js", ".py"])');
      return { rule: null, errors };
    }
    fileExtensions = raw.fileExtensions.filter(
      ext => typeof ext === 'string' && ext.startsWith('.')
    );
    if (fileExtensions.length === 0) fileExtensions = null;
  }

  const references = Array.isArray(raw.references)
    ? raw.references.filter(r => typeof r === 'string')
    : [];
  const mitre = (raw.mitre && typeof raw.mitre === 'string') ? raw.mitre : null;

  const typeKey = `custom_${folderName}`;

  return {
    rule: {
      typeKey,
      id: String(id).trim(),
      name: String(name).trim(),
      severity,
      confidence,
      description: String(description).trim(),
      references,
      mitre,
      patterns: compiledPatterns,
      fileExtensions
    },
    errors: []
  };
}

/**
 * Load all custom rules from a single base directory.
 * @param {string} baseDir
 * @returns {{ rules: object[], warnings: string[] }}
 */
function loadCustomRulesFromDir(baseDir) {
  const rules = [];
  const warnings = [];

  if (!fs.existsSync(baseDir)) return { rules, warnings };

  let entries;
  try {
    entries = fs.readdirSync(baseDir);
  } catch (e) {
    warnings.push(`Cannot read custom rules directory "${baseDir}": ${e.message}`);
    return { rules, warnings };
  }

  let ruleCount = 0;
  for (const entry of entries) {
    if (ruleCount >= MAX_CUSTOM_RULES) {
      warnings.push(`Custom rules limit (${MAX_CUSTOM_RULES}) reached — remaining entries ignored`);
      break;
    }

    const folderPath = path.join(baseDir, entry);
    let lstat;
    try {
      lstat = fs.lstatSync(folderPath);
    } catch {
      continue;
    }
    if (!lstat.isDirectory()) continue;

    const ruleJsonPath = path.join(folderPath, 'rule.json');
    if (!fs.existsSync(ruleJsonPath)) {
      warnings.push(`Custom rule folder "${entry}": missing rule.json — skipped`);
      continue;
    }

    let fileStat;
    try {
      fileStat = fs.statSync(ruleJsonPath);
    } catch {
      continue;
    }
    if (fileStat.size > MAX_CUSTOM_RULE_FILE_SIZE) {
      warnings.push(`Custom rule "${entry}/rule.json" exceeds 64KB limit — skipped`);
      continue;
    }

    let raw;
    try {
      const content = fs.readFileSync(ruleJsonPath, 'utf8');
      raw = JSON.parse(content);
    } catch (e) {
      warnings.push(`Custom rule "${entry}/rule.json" parse error: ${e.message} — skipped`);
      continue;
    }

    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      warnings.push(`Custom rule "${entry}/rule.json" must contain a JSON object — skipped`);
      continue;
    }

    const { rule, errors } = validateCustomRule(entry, raw);
    if (errors.length > 0) {
      for (const err of errors) {
        warnings.push(`Custom rule "${entry}": ${err} — skipped`);
      }
      continue;
    }

    rules.push(rule);
    ruleCount++;
    debugLog(`[CUSTOM-RULES] Loaded rule "${entry}" (type: ${rule.typeKey}, severity: ${rule.severity})`);
  }

  return { rules, warnings };
}

/**
 * Scan a target directory using all loaded custom rules.
 * @param {string} targetPath - directory to scan
 * @param {object} options - CLI options ({ customRulesDir?: string })
 * @param {string[]} warnings - mutable warnings array (populated with load errors)
 * @returns {Array} threats
 */
function scanCustomRules(targetPath, options, warnings) {
  const threats = [];

  const dirs = resolveCustomRulesDirs(targetPath, (options && options.customRulesDir) || null);

  const allRules = [];
  for (const dir of dirs) {
    const { rules, warnings: w } = loadCustomRulesFromDir(dir);
    allRules.push(...rules);
    if (w.length > 0) warnings.push(...w);
  }

  if (allRules.length === 0) return threats;

  // Register definitions so getRule() can enrich these threats later
  registerCustomRules(allRules);

  // Collect the union of extensions needed across all rules
  const extSet = new Set();
  let needAllDefaults = false;
  for (const rule of allRules) {
    if (rule.fileExtensions) {
      for (const ext of rule.fileExtensions) extSet.add(ext);
    } else {
      needAllDefaults = true;
    }
  }
  const scanExtensions = needAllDefaults
    ? DEFAULT_SCAN_EXTENSIONS
    : [...extSet];

  if (scanExtensions.length === 0) return threats;

  const files = findFiles(targetPath, { extensions: scanExtensions });
  const maxSize = getMaxFileSize();

  for (const filePath of files) {
    let stat;
    try {
      stat = fs.statSync(filePath);
    } catch {
      continue;
    }
    if (stat.size > maxSize) continue;

    const relFile = path.relative(targetPath, filePath) || filePath;
    const ext = path.extname(filePath).toLowerCase();
    let content = null;

    for (const rule of allRules) {
      // Apply per-rule extension filter
      if (rule.fileExtensions && !rule.fileExtensions.includes(ext)) continue;

      // Lazy-load file content
      if (content === null) {
        try {
          content = fs.readFileSync(filePath, 'utf8');
        } catch {
          break;
        }
      }

      for (const { compiled, message } of rule.patterns) {
        // Reset lastIndex for RegExp objects with the global flag; no-op for others
        compiled.lastIndex = 0;
        const match = compiled.exec(content);
        if (match) {
          const line = content.substring(0, match.index).split('\n').length;
          const matchedText = match[0].slice(0, MAX_MATCHED_TEXT_LENGTH);
          threats.push({
            type: rule.typeKey,
            severity: rule.severity,
            message: `[${rule.name}] ${message}`,
            file: relFile,
            line,
            matchedText
          });
          break; // one threat per rule per file is sufficient
        }
      }
    }
  }

  return threats;
}

module.exports = { scanCustomRules, loadCustomRulesFromDir, resolveCustomRulesDirs, validateCustomRule };
