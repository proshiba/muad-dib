const fs = require('fs');
const path = require('path');
const https = require('https');

const CACHE_PATH = path.join(__dirname, '../../.muaddib-cache');
const IOC_FILE = path.join(CACHE_PATH, 'iocs.json');

const BUILTIN_IOCS = {
  packages: [
    { name: '@ctrl/tinycolor', version: '4.1.1', source: 'shai-hulud-v1' },
    { name: 'flatmap-stream', version: '*', source: 'event-stream' },
    { name: 'event-stream', version: '3.3.6', source: 'event-stream' },
    { name: 'eslint-scope', version: '3.7.2', source: 'eslint-scope' },
    { name: '@asyncapi/specs', version: '*', source: 'shai-hulud-v2' },
    { name: 'get-them-args', version: '*', source: 'shai-hulud-v2' },
    { name: 'kill-port', version: '*', source: 'shai-hulud-v2' },
    { name: 'posthog-node', version: '*', source: 'shai-hulud-v2' },
    { name: 'posthog-js', version: '*', source: 'shai-hulud-v2' },
    { name: '@postman/tunnel-agent', version: '*', source: 'shai-hulud-v2' }
  ],
  files: [
    'setup_bun.js',
    'bun_environment.js',
    'bundle.js'
  ],
  hashes: [
    '62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0',
    'cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd',
    'f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068',
    'a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a',
    'f1df4896244500671eb4aa63ebb48ea11cee196fafaa0e9874e17b24ac053c02',
    '9d59fd0bcc14b671079824c704575f201b74276238dc07a9c12a93a84195648a',
    'e0250076c1d2ac38777ea8f542431daf61fcbaab0ca9c196614b28065ef5b918'
  ],
  markers: [
    'Sha1-Hulud',
    'Shai-Hulud',
    'The Second Coming',
    'Goldox-T3chs',
    'Only Happy Girl'
  ]
};

const EXTERNAL_FEEDS = [
  {
    name: 'socket-npm-malware',
    url: 'https://raw.githubusercontent.com/nickvidal/awesome-malicious-packages/main/src/packages/npm.json',
    parser: parseSocketFeed
  }
];

async function updateIOCs() {
  console.log('[MUADDIB] Mise a jour des IOCs...\n');

  if (!fs.existsSync(CACHE_PATH)) {
    fs.mkdirSync(CACHE_PATH, { recursive: true });
  }

  // Commence avec les IOCs integres
  const iocs = JSON.parse(JSON.stringify(BUILTIN_IOCS));

  // Tente de recuperer les feeds externes
  for (const feed of EXTERNAL_FEEDS) {
    try {
      console.log(`[INFO] Telechargement depuis ${feed.name}...`);
      const data = await fetchUrl(feed.url);
      const packages = feed.parser(data);
      
      // Ajoute sans doublons
      for (const pkg of packages) {
        if (!iocs.packages.find(p => p.name === pkg.name)) {
          iocs.packages.push(pkg);
        }
      }
      
      console.log(`[OK] ${packages.length} IOCs recuperes de ${feed.name}`);
    } catch (err) {
      console.log(`[WARN] Echec ${feed.name}: ${err.message}`);
    }
  }

  iocs.updated = new Date().toISOString();

  fs.writeFileSync(IOC_FILE, JSON.stringify(iocs, null, 2));
  console.log(`\n[OK] IOCs sauvegardes:`);
  console.log(`     - ${iocs.packages.length} packages malveillants`);
  console.log(`     - ${iocs.files.length} fichiers suspects`);
  console.log(`     - ${iocs.hashes.length} hashes connus`);
  console.log(`     - ${iocs.markers.length} marqueurs\n`);

  return iocs;
}

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode === 301 || res.statusCode === 302) {
        fetchUrl(res.headers.location).then(resolve).catch(reject);
        return;
      }
      if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode}`));
        return;
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

function parseSocketFeed(data) {
  const packages = [];
  try {
    const json = JSON.parse(data);
    if (Array.isArray(json)) {
      for (const item of json) {
        if (item.name) {
          packages.push({
            name: item.name,
            version: item.version || '*',
            source: 'socket-feed'
          });
        }
      }
    }
  } catch (e) {
    // Parse error
  }
  return packages;
}

function loadCachedIOCs() {
  if (fs.existsSync(IOC_FILE)) {
    return JSON.parse(fs.readFileSync(IOC_FILE, 'utf8'));
  }
  return BUILTIN_IOCS;
}

module.exports = { updateIOCs, loadCachedIOCs };