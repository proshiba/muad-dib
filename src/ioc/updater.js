const https = require('https');
const fs = require('fs');
const path = require('path');

const IOC_SOURCES = [
  {
    name: 'datadog',
    url: 'https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/malicious.jsonl'
  }
];

const CACHE_PATH = path.join(__dirname, '../../.muaddib-cache');
const IOC_FILE = path.join(CACHE_PATH, 'iocs.json');

async function updateIOCs() {
  console.log('[MUADDIB] Mise a jour des IOCs...\n');

  if (!fs.existsSync(CACHE_PATH)) {
    fs.mkdirSync(CACHE_PATH, { recursive: true });
  }

  const iocs = {
    packages: [],
    hashes: [],
    updated: new Date().toISOString()
  };

  for (const source of IOC_SOURCES) {
    try {
      console.log(`[INFO] Telechargement depuis ${source.name}...`);
      const data = await fetch(source.url);
      const packages = parseIOCs(data, source.name);
      iocs.packages.push(...packages);
      console.log(`[OK] ${packages.length} IOCs recuperes de ${source.name}`);
    } catch (err) {
      console.log(`[ERREUR] Echec ${source.name}: ${err.message}`);
    }
  }

  fs.writeFileSync(IOC_FILE, JSON.stringify(iocs, null, 2));
  console.log(`\n[OK] ${iocs.packages.length} IOCs sauvegardes dans ${IOC_FILE}\n`);

  return iocs;
}

function fetch(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
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

function parseIOCs(data, source) {
  const packages = [];
  const lines = data.split('\n').filter(l => l.trim());

  for (const line of lines) {
    try {
      const obj = JSON.parse(line);
      if (obj.name) {
        packages.push({
          name: obj.name,
          version: obj.version || '*',
          source: source
        });
      }
    } catch (e) {
      // Ligne non-JSON, ignore
    }
  }

  return packages;
}

function loadCachedIOCs() {
  if (fs.existsSync(IOC_FILE)) {
    return JSON.parse(fs.readFileSync(IOC_FILE, 'utf8'));
  }
  return { packages: [], hashes: [], updated: null };
}

module.exports = { updateIOCs, loadCachedIOCs };