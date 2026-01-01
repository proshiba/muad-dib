const fs = require('fs');
const path = require('path');

const CACHE_PATH = path.join(__dirname, '../../.muaddib-cache');
const IOC_FILE = path.join(CACHE_PATH, 'iocs.json');

async function updateIOCs() {
  console.log('[MUADDIB] Mise a jour des IOCs...\n');

  if (!fs.existsSync(CACHE_PATH)) {
    fs.mkdirSync(CACHE_PATH, { recursive: true });
  }

  const iocs = {
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
      'a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a'
    ],
    markers: [
      'Sha1-Hulud',
      'Shai-Hulud',
      'The Second Coming',
      'Goldox-T3chs'
    ],
    updated: new Date().toISOString()
  };

  fs.writeFileSync(IOC_FILE, JSON.stringify(iocs, null, 2));
  console.log(`[OK] IOCs sauvegardes:`);
  console.log(`     - ${iocs.packages.length} packages malveillants`);
  console.log(`     - ${iocs.files.length} fichiers suspects`);
  console.log(`     - ${iocs.hashes.length} hashes connus`);
  console.log(`     - ${iocs.markers.length} marqueurs\n`);

  return iocs;
}

function loadCachedIOCs() {
  if (fs.existsSync(IOC_FILE)) {
    return JSON.parse(fs.readFileSync(IOC_FILE, 'utf8'));
  }
  return { packages: [], files: [], hashes: [], markers: [], updated: null };
}


module.exports = { updateIOCs, loadCachedIOCs }; 