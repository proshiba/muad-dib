const fs = require('fs');
const path = require('path');
const https = require('https');

const CACHE_PATH = path.join(__dirname, '../../.muaddib-cache');
const IOC_FILE = path.join(CACHE_PATH, 'iocs.json');
const { loadYAMLIOCs, getIOCStats } = require('./yaml-loader.js');

const BUILTIN_IOCS = {
  packages: [
    // Shai-Hulud v1 (septembre 2025)
    { name: '@ctrl/tinycolor', version: '4.1.1', source: 'shai-hulud-v1' },
    { name: 'ng2-file-upload', version: '*', source: 'shai-hulud-v1' },
    { name: 'ngx-bootstrap', version: '*', source: 'shai-hulud-v1' },
    
    // Shai-Hulud v2 (novembre 2025)
    { name: '@asyncapi/specs', version: '*', source: 'shai-hulud-v2' },
    { name: '@asyncapi/openapi-schema-parser', version: '*', source: 'shai-hulud-v2' },
    { name: 'get-them-args', version: '*', source: 'shai-hulud-v2' },
    { name: 'kill-port', version: '*', source: 'shai-hulud-v2' },
    { name: 'shell-exec', version: '*', source: 'shai-hulud-v2' },
    { name: 'posthog-node', version: '*', source: 'shai-hulud-v2' },
    { name: 'posthog-js', version: '*', source: 'shai-hulud-v2' },
    { name: '@postman/tunnel-agent', version: '*', source: 'shai-hulud-v2' },
    { name: '@zapier/secret-scrubber', version: '*', source: 'shai-hulud-v2' },
    
    // Shai-Hulud v3 Golden Path (decembre 2025)
    { name: '@vietmoney/react-big-calendar', version: '0.26.2', source: 'shai-hulud-v3' },
    
    // Attaques historiques
    { name: 'flatmap-stream', version: '0.1.1', source: 'event-stream-2018' },
    { name: 'event-stream', version: '3.3.6', source: 'event-stream-2018' },
    { name: 'eslint-scope', version: '3.7.2', source: 'eslint-scope-2018' },
    { name: 'eslint-config-prettier', version: '8.10.1', source: 'eslint-prettier-2025' },
    { name: 'eslint-config-prettier', version: '9.1.1', source: 'eslint-prettier-2025' },
    { name: 'eslint-plugin-prettier', version: '4.2.2', source: 'eslint-prettier-2025' },
    { name: 'synckit', version: '0.11.9', source: 'eslint-prettier-2025' },
    { name: '@pkgr/core', version: '0.2.8', source: 'eslint-prettier-2025' },
    { name: 'napi-postinstall', version: '0.3.1', source: 'eslint-prettier-2025' },
    { name: 'got-fetch', version: '5.1.11', source: 'eslint-prettier-2025' },
    { name: 'is', version: '3.3.1', source: 'is-package-2025' },
    { name: 'is', version: '5.0.0', source: 'is-package-2025' },
    
    // Typosquats connus
    { name: 'crossenv', version: '*', source: 'typosquat' },
    { name: 'cross-env.js', version: '*', source: 'typosquat' },
    { name: 'mongose', version: '*', source: 'typosquat' },
    { name: 'mssql.js', version: '*', source: 'typosquat' },
    { name: 'mssql-node', version: '*', source: 'typosquat' },
    { name: 'babelcli', version: '*', source: 'typosquat' },
    { name: 'http-proxy.js', version: '*', source: 'typosquat' },
    { name: 'proxy.js', version: '*', source: 'typosquat' },
    { name: 'shadowsock', version: '*', source: 'typosquat' },
    { name: 'smb', version: '*', source: 'typosquat' },
    { name: 'nodesass', version: '*', source: 'typosquat' },
    { name: 'node-sass.js', version: '*', source: 'typosquat' },
    
    // Protestware
    { name: 'node-ipc', version: '10.1.1', source: 'protestware' },
    { name: 'node-ipc', version: '10.1.2', source: 'protestware' },
    { name: 'node-ipc', version: '10.1.3', source: 'protestware' },
    { name: 'colors', version: '1.4.1', source: 'protestware' },
    { name: 'colors', version: '1.4.2', source: 'protestware' },
    { name: 'faker', version: '6.6.6', source: 'protestware' }
  ],
  files: [
    'setup_bun.js',
    'bun_environment.js',
    'bundle.js',
    'node-gyp.dll',
    'preinstall.js',
    'postinstall.js',
    'install.js'
  ],
  hashes: [
    '62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0',
    'cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd',
    'f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068',
    'a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a',
    'f1df4896244500671eb4aa63ebb48ea11cee196fafaa0e9874e17b24ac053c02',
    '9d59fd0bcc14b671079824c704575f201b74276238dc07a9c12a93a84195648a',
    'e0250076c1d2ac38777ea8f542431daf61fcbaab0ca9c196614b28065ef5b918',
    '6c9628f72d2bb789fe8f097a611d61c8c53f2f21e47c6a5d8d3e0e0b8e5e8c8f',
    'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
    '4b2399646573bb737c4969563303d8ee2e9ddbd1b271f1ca9e35ea78062538db',
    '46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09',
    'b74caeaa75e077c99f7d44f46daaf9796a3be43ecf24f2a1fd381844669da777',
    'dc67467a39b70d1cd4c1f7f7a459b35058163592f4a9e8fb4dffcbba98ef210c'
  ],
  markers: [
    'Sha1-Hulud',
    'Shai-Hulud',
    'The Second Coming',
    'Goldox-T3chs',
    'Only Happy Girl',
    'peacenotwar',
    'protestware',
    '/dev/tcp',
    'reverse shell'
  ]
};

const EXTERNAL_FEEDS = [
  {
    name: 'muaddib-community',
    url: 'https://raw.githubusercontent.com/DNSZLSK/muad-dib/master/data/iocs.json',
    parser: parseMuaddibFeed
  }
];

async function updateIOCs() {
  console.log('[MUADDIB] Mise a jour des IOCs...\n');

  if (!fs.existsSync(CACHE_PATH)) {
    fs.mkdirSync(CACHE_PATH, { recursive: true });
  }

  const iocs = JSON.parse(JSON.stringify(BUILTIN_IOCS));

  for (const feed of EXTERNAL_FEEDS) {
    try {
      console.log(`[INFO] Telechargement depuis ${feed.name}...`);
      const data = await fetchUrl(feed.url);
      const externalIOCs = feed.parser(data);
      
      // Merge packages
      for (const pkg of externalIOCs.packages || []) {
        if (!iocs.packages.find(p => p.name === pkg.name && p.version === pkg.version)) {
          iocs.packages.push(pkg);
        }
      }
      
      // Merge hashes
      for (const hash of externalIOCs.hashes || []) {
        if (!iocs.hashes.includes(hash)) {
          iocs.hashes.push(hash);
        }
      }
      
      // Merge markers
      for (const marker of externalIOCs.markers || []) {
        if (!iocs.markers.includes(marker)) {
          iocs.markers.push(marker);
        }
      }
      
      // Merge files
      for (const file of externalIOCs.files || []) {
        if (!iocs.files.includes(file)) {
          iocs.files.push(file);
        }
      }
      
      console.log(`[OK] IOCs externes merges depuis ${feed.name}`);
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

function parseMuaddibFeed(data) {
  try {
    return JSON.parse(data);
  } catch (e) {
    return { packages: [], hashes: [], markers: [], files: [] };
  }
}

function loadCachedIOCs() {
  // Priorite 1 : IOCs YAML locaux
  const yamlIOCs = loadYAMLIOCs();
  
  // Priorite 2 : Cache telecharge
  let cachedIOCs = { packages: [], hashes: [], markers: [], files: [] };
  if (fs.existsSync(IOC_FILE)) {
    cachedIOCs = JSON.parse(fs.readFileSync(IOC_FILE, 'utf8'));
  }
  
  // Merge : YAML + Cache + Builtin
  const merged = {
    packages: [...yamlIOCs.packages],
    hashes: yamlIOCs.hashes.map(h => h.sha256),
    markers: yamlIOCs.markers.map(m => m.pattern),
    files: yamlIOCs.files.map(f => f.name)
  };
  
  // Ajouter les IOCs du cache sans doublons
  for (const pkg of cachedIOCs.packages || []) {
    if (!merged.packages.find(p => p.name === pkg.name)) {
      merged.packages.push(pkg);
    }
  }
  
  for (const hash of cachedIOCs.hashes || []) {
    if (!merged.hashes.includes(hash)) {
      merged.hashes.push(hash);
    }
  }
  
  for (const marker of cachedIOCs.markers || []) {
    if (!merged.markers.includes(marker)) {
      merged.markers.push(marker);
    }
  }
  
  for (const file of cachedIOCs.files || []) {
    if (!merged.files.includes(file)) {
      merged.files.push(file);
    }
  }
  
  return merged;
}

module.exports = { updateIOCs, loadCachedIOCs };