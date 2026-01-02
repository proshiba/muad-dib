const https = require('https');
const fs = require('fs');
const path = require('path');

const IOC_FILE = path.join(__dirname, '../../data/iocs.json');

async function fetchJSON(url, options = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const reqOptions = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: options.method || 'GET',
      headers: {
        'User-Agent': 'MUADDIB-Scanner/1.0',
        'Accept': 'application/json',
        ...options.headers
      }
    };

    const req = https.request(reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch (e) {
          resolve({ status: res.statusCode, data: null, error: e.message });
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(10000, () => {
      req.destroy();
      reject(new Error('Timeout'));
    });
    
    if (options.body) {
      req.write(JSON.stringify(options.body));
    }
    
    req.end();
  });
}

// ============================================
// SOURCE 1: GitHub Security Advisories
// ============================================
async function scrapeGitHubAdvisories() {
  console.log('[SCRAPER] GitHub Security Advisories...');
  const packages = [];
  
  try {
    // Plusieurs pages
    for (let page = 1; page <= 5; page++) {
      const url = `https://api.github.com/advisories?ecosystem=npm&per_page=100&page=${page}`;
      const { status, data } = await fetchJSON(url);
      
      if (status !== 200 || !Array.isArray(data)) break;
      if (data.length === 0) break;
      
      for (const advisory of data) {
        if (advisory.severity === 'critical' || advisory.severity === 'high') {
          for (const vuln of advisory.vulnerabilities || []) {
            if (vuln.package?.ecosystem === 'npm') {
              packages.push({
                id: advisory.ghsa_id || `GHSA-${Date.now()}`,
                name: vuln.package.name,
                version: vuln.vulnerable_version_range || '*',
                severity: advisory.severity,
                confidence: 'high',
                source: 'github-advisory',
                description: (advisory.summary || '').slice(0, 200),
                references: [advisory.html_url].filter(Boolean),
                mitre: 'T1195.002',
                cve: advisory.cve_id
              });
            }
          }
        }
      }
    }
    console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  } catch (e) {
    console.log(`[SCRAPER]   -> Erreur: ${e.message}`);
  }
  
  return packages;
}

// ============================================
// SOURCE 2: OSV.dev (Open Source Vulnerabilities)
// ============================================
async function scrapeOSV() {
  console.log('[SCRAPER] OSV.dev...');
  const packages = [];
  
  try {
    // Query malware specifique
    const queries = [
      { package: { ecosystem: 'npm' }, query: 'malware' },
      { package: { ecosystem: 'npm' }, query: 'malicious' },
      { package: { ecosystem: 'npm' }, query: 'typosquat' }
    ];
    
    for (const q of queries) {
      const { status, data } = await fetchJSON('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: { package: q.package }
      });
      
      if (status === 200 && data?.vulns) {
        for (const vuln of data.vulns) {
          for (const affected of vuln.affected || []) {
            if (affected.package?.ecosystem === 'npm') {
              packages.push({
                id: vuln.id,
                name: affected.package.name,
                version: '*',
                severity: 'high',
                confidence: 'high',
                source: 'osv',
                description: (vuln.summary || vuln.details || '').slice(0, 200),
                references: (vuln.references || []).map(r => r.url).slice(0, 2),
                mitre: 'T1195.002'
              });
            }
          }
        }
      }
    }
    console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  } catch (e) {
    console.log(`[SCRAPER]   -> Erreur: ${e.message}`);
  }
  
  return packages;
}

// ============================================
// SOURCE 3: Snyk Vulnerability DB (publique)
// ============================================
async function scrapeSnyk() {
  console.log('[SCRAPER] Snyk Vulnerability DB...');
  const packages = [];
  
  // Packages malveillants connus de Snyk (liste statique car API payante)
  const knownMalicious = [
    'event-stream', 'flatmap-stream', 'eslint-scope', 'eslint-config-eslint',
    'getcookies', 'mailparser', 'nodemailer', 'nodemailer-js', 'node-ipc',
    'peacenotwar', 'colors', 'faker', 'ua-parser-js', 'rc', 'coa',
    'pac-resolver', 'set-value', 'ansi-html', 'ini', 'y18n', 'node-notifier',
    'trim', 'trim-newlines', 'glob-parent', 'is-svg', 'css-what', 'normalize-url',
    'hosted-git-info', 'ssri', 'tar', 'path-parse', 'json-schema',
    'underscore', 'handlebars', 'lodash', 'marked', 'minimist', 'kind-of'
  ];
  
  // On ne les ajoute que s'ils ont des versions malveillantes specifiques
  // Pour l'instant on skip car c'est trop de faux positifs
  console.log(`[SCRAPER]   -> Skip (API payante)`);
  
  return packages;
}

// ============================================
// SOURCE 4: Socket.dev (via leur blog/reports)
// ============================================
async function scrapeSocketReports() {
  console.log('[SCRAPER] Socket.dev reports...');
  const packages = [];
  
  // Packages malveillants reportes par Socket.dev
  const socketMalicious = [
    // Shai-Hulud variants
    { name: '@pnpm.exe/pnpm', severity: 'critical', source: 'socket-shai-hulud' },
    { name: '@nicklason/npm', severity: 'critical', source: 'socket-shai-hulud' },
    { name: 'bb-builder', severity: 'critical', source: 'socket-shai-hulud' },
    { name: 'codespaces-blank', severity: 'critical', source: 'socket-shai-hulud' },
    // Crypto stealers
    { name: 'crypto-browserify-aes', severity: 'critical', source: 'socket-crypto-stealer' },
    { name: 'eth-wallet-gen', severity: 'critical', source: 'socket-crypto-stealer' },
    { name: 'solana-wallet-tools', severity: 'critical', source: 'socket-crypto-stealer' },
    // Discord token stealers
    { name: 'discord-selfbot-tools', severity: 'critical', source: 'socket-discord-stealer' },
    { name: 'discord-selfbot-v13', severity: 'critical', source: 'socket-discord-stealer' },
    { name: 'discord-token-grabber', severity: 'critical', source: 'socket-discord-stealer' },
    { name: 'discordbot-tokens', severity: 'critical', source: 'socket-discord-stealer' },
    // Typosquats recents
    { name: 'electorn', severity: 'high', source: 'socket-typosquat' },
    { name: 'electrn', severity: 'high', source: 'socket-typosquat' },
    { name: 'reqeusts', severity: 'high', source: 'socket-typosquat' },
    { name: 'requets', severity: 'high', source: 'socket-typosquat' },
    { name: 'requsests', severity: 'high', source: 'socket-typosquat' },
    { name: 'axois', severity: 'high', source: 'socket-typosquat' },
    { name: 'axio', severity: 'high', source: 'socket-typosquat' },
    { name: 'lodahs', severity: 'high', source: 'socket-typosquat' },
    { name: 'lodasg', severity: 'high', source: 'socket-typosquat' },
    { name: 'expres', severity: 'high', source: 'socket-typosquat' },
    { name: 'expresss', severity: 'high', source: 'socket-typosquat' },
    { name: 'momnet', severity: 'high', source: 'socket-typosquat' },
    { name: 'monment', severity: 'high', source: 'socket-typosquat' },
    { name: 'recat', severity: 'high', source: 'socket-typosquat' },
    { name: 'reactt', severity: 'high', source: 'socket-typosquat' },
    { name: 'chalks', severity: 'high', source: 'socket-typosquat' },
    { name: 'chalkk', severity: 'high', source: 'socket-typosquat' },
    // Protestware
    { name: 'styled-components-native', severity: 'high', source: 'socket-protestware' },
    { name: 'es5-ext', severity: 'medium', source: 'socket-protestware' }
  ];
  
  for (const pkg of socketMalicious) {
    packages.push({
      id: `SOCKET-${pkg.name}`,
      name: pkg.name,
      version: '*',
      severity: pkg.severity,
      confidence: 'high',
      source: pkg.source,
      description: `Malicious package reported by Socket.dev`,
      references: ['https://socket.dev/npm/package/' + pkg.name],
      mitre: 'T1195.002'
    });
  }
  
  console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  return packages;
}

// ============================================
// SOURCE 5: Phylum Research
// ============================================
async function scrapePhylum() {
  console.log('[SCRAPER] Phylum Research...');
  const packages = [];
  
  // Packages malveillants reportes par Phylum
  const phylumMalicious = [
    // Shai-Hulud original
    { name: '@nicklason/npm-register', severity: 'critical' },
    { name: 'lemaaa', severity: 'critical' },
    { name: 'badshell', severity: 'critical' },
    // Reverse shells
    { name: 'node-shell', severity: 'critical' },
    { name: 'reverse-shell-as-a-service', severity: 'critical' },
    // Data exfiltration
    { name: 'browserify-sign-steal', severity: 'critical' },
    { name: 'npm-script-demo', severity: 'high' },
    // Malware loaders
    { name: 'load-from-cwd-or-npm', severity: 'high' },
    { name: 'loadyaml-', severity: 'high' },
    // Install scripts malicious
    { name: 'preinstall-script', severity: 'high' },
    { name: 'postinstall-script', severity: 'high' }
  ];
  
  for (const pkg of phylumMalicious) {
    packages.push({
      id: `PHYLUM-${pkg.name}`,
      name: pkg.name,
      version: '*',
      severity: pkg.severity,
      confidence: 'high',
      source: 'phylum',
      description: `Malicious package reported by Phylum Research`,
      references: ['https://blog.phylum.io'],
      mitre: 'T1195.002'
    });
  }
  
  console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  return packages;
}

// ============================================
// SOURCE 6: npm unpublished/removed packages
// ============================================
async function scrapeNpmRemoved() {
  console.log('[SCRAPER] npm removed packages...');
  const packages = [];
  
  // Packages retires de npm pour raisons de securite
  const removedPackages = [
    { name: 'event-stream', version: '3.3.6', reason: 'Malicious code injection' },
    { name: 'flatmap-stream', version: '0.1.1', reason: 'Bitcoin wallet stealer' },
    { name: 'eslint-scope', version: '3.7.2', reason: 'npm token stealer' },
    { name: 'eslint-config-eslint', version: '5.0.2', reason: 'npm token stealer' },
    { name: 'getcookies', version: '*', reason: 'Backdoor' },
    { name: 'mailparser', version: '2.0.5', reason: 'Malicious code' },
    { name: 'bootstrap-sass', version: '3.4.1', reason: 'Backdoor injection' },
    { name: 'twilio-npm', version: '*', reason: 'Typosquat malware' },
    { name: 'discord.js-self', version: '*', reason: 'Token stealer' },
    { name: 'fallguys', version: '*', reason: 'Malware' },
    { name: 'am-i-going-to-miss-my-flight', version: '*', reason: 'Test malware' }
  ];
  
  for (const pkg of removedPackages) {
    packages.push({
      id: `NPM-REMOVED-${pkg.name}`,
      name: pkg.name,
      version: pkg.version,
      severity: 'critical',
      confidence: 'high',
      source: 'npm-removed',
      description: `Removed from npm: ${pkg.reason}`,
      references: ['https://www.npmjs.com/policies/security'],
      mitre: 'T1195.002'
    });
  }
  
  console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  return packages;
}

// ============================================
// SOURCE 7: Known typosquats generator
// ============================================
async function generateTyposquats() {
  console.log('[SCRAPER] Typosquats generation...');
  const packages = [];
  
  // Top packages npm et leurs typosquats connus
  const typosquatMap = {
    'lodash': ['lodahs', 'lodasg', 'lodash-', '-lodash', 'lodas', 'lodashh'],
    'express': ['expres', 'expresss', 'exprees', 'exprss', 'exppress'],
    'react': ['recat', 'reactt', 'reacct', 'raect', 'reactjs-', 'reakt'],
    'axios': ['axois', 'axio', 'axioss', 'axiso', 'axius'],
    'moment': ['momnet', 'monment', 'momment', 'momet', 'momentt'],
    'chalk': ['chalks', 'chalkk', 'chlak', 'chalck'],
    'commander': ['comander', 'commanderr', 'comandr'],
    'webpack': ['webpck', 'webpak', 'weback', 'webpackk'],
    'typescript': ['typscript', 'typsecript', 'typescrip', 'typescipt'],
    'eslint': ['eslit', 'eslnt', 'esllint', 'eslintjs'],
    'prettier': ['pretier', 'pretiier', 'prittier', 'prettir'],
    'mongoose': ['mongose', 'mongoos', 'mongoosee', 'mongooose'],
    'electron': ['electorn', 'electrn', 'elctron', 'elecrton'],
    'puppeteer': ['pupeteer', 'puppetter', 'pupetear', 'puppetee'],
    'dotenv': ['dotevn', 'doteenv', 'dotnev', 'dotenv-'],
    'uuid': ['uuidd', 'uudi', 'uud', 'uuid-js'],
    'bcrypt': ['bcript', 'bcryt', 'bcrytp', 'bycrpt'],
    'jsonwebtoken': ['jsonwebtokn', 'jsonwebtoke', 'jwttoken'],
    'nodemailer': ['nodemailr', 'nodemailler', 'nodemalier'],
    'socket.io': ['socketio', 'socet.io', 'socket-io-', 'soket.io']
  };
  
  for (const [original, typos] of Object.entries(typosquatMap)) {
    for (const typo of typos) {
      packages.push({
        id: `TYPO-${typo}`,
        name: typo,
        version: '*',
        severity: 'high',
        confidence: 'medium',
        source: 'typosquat-db',
        description: `Potential typosquat of "${original}"`,
        references: [],
        mitre: 'T1195.002'
      });
    }
  }
  
  console.log(`[SCRAPER]   -> ${packages.length} packages trouves`);
  return packages;
}

// ============================================
// MAIN SCRAPER
// ============================================
async function runScraper() {
  console.log('\n╔════════════════════════════════════════════╗');
  console.log('║      MUAD\'DIB IOC Scraper                  ║');
  console.log('╚════════════════════════════════════════════╝\n');
  
  // Charger les IOCs existants
  let existingIOCs = { packages: [], hashes: [], markers: [], files: [] };
  if (fs.existsSync(IOC_FILE)) {
    existingIOCs = JSON.parse(fs.readFileSync(IOC_FILE, 'utf8'));
  }
  
  const existingNames = new Set(existingIOCs.packages.map(p => p.name));
  const initialCount = existingIOCs.packages.length;
  
  // Scraper toutes les sources
  const results = await Promise.all([
    scrapeGitHubAdvisories(),
    scrapeOSV(),
    scrapeSocketReports(),
    scrapePhylum(),
    scrapeNpmRemoved(),
    generateTyposquats()
  ]);
  
  // Fusionner sans doublons
  let added = 0;
  for (const pkgList of results) {
    for (const pkg of pkgList) {
      if (!existingNames.has(pkg.name)) {
        existingIOCs.packages.push(pkg);
        existingNames.add(pkg.name);
        added++;
      }
    }
  }
  
  // Sauvegarder
  fs.writeFileSync(IOC_FILE, JSON.stringify(existingIOCs, null, 2));
  
  console.log('\n╔════════════════════════════════════════════╗');
  console.log('║      Resultats                             ║');
  console.log('╚════════════════════════════════════════════╝');
  console.log(`  IOCs avant:     ${initialCount}`);
  console.log(`  Nouveaux:       ${added}`);
  console.log(`  Total:          ${existingIOCs.packages.length}`);
  console.log(`  Fichier:        ${IOC_FILE}\n`);
  
  return { added, total: existingIOCs.packages.length };
}

module.exports = { runScraper };