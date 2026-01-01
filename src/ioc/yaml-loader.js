const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');

const IOCS_DIR = path.join(__dirname, '../../iocs');

function loadYAMLIOCs() {
  const iocs = {
    packages: [],
    hashes: [],
    markers: [],
    files: []
  };

  // Charger packages.yaml
  const packagesPath = path.join(IOCS_DIR, 'packages.yaml');
  if (fs.existsSync(packagesPath)) {
    try {
      const data = yaml.load(fs.readFileSync(packagesPath, 'utf8'));
      if (data && data.packages) {
        iocs.packages = data.packages.map(p => ({
          id: p.id,
          name: p.name,
          version: p.version,
          severity: p.severity,
          confidence: p.confidence,
          source: p.source,
          description: p.description,
          references: p.references || [],
          mitre: p.mitre
        }));
      }
    } catch (e) {
      console.error('[WARN] Erreur parsing packages.yaml:', e.message);
    }
  }

  // Charger hashes.yaml
  const hashesPath = path.join(IOCS_DIR, 'hashes.yaml');
  if (fs.existsSync(hashesPath)) {
    try {
      const data = yaml.load(fs.readFileSync(hashesPath, 'utf8'));
      
      if (data && data.hashes) {
        iocs.hashes = data.hashes.map(h => ({
          id: h.id,
          sha256: h.sha256,
          file: h.file,
          severity: h.severity,
          confidence: h.confidence,
          source: h.source,
          description: h.description,
          references: h.references || []
        }));
      }
      
      if (data && data.markers) {
        iocs.markers = data.markers.map(m => ({
          id: m.id,
          pattern: m.pattern,
          severity: m.severity,
          confidence: m.confidence,
          source: m.source,
          description: m.description
        }));
      }
      
      if (data && data.files) {
        iocs.files = data.files.map(f => ({
          id: f.id,
          name: f.name,
          severity: f.severity,
          confidence: f.confidence,
          source: f.source,
          description: f.description
        }));
      }
    } catch (e) {
      console.error('[WARN] Erreur parsing hashes.yaml:', e.message);
    }
  }

  return iocs;
}

function getIOCStats() {
  const iocs = loadYAMLIOCs();
  return {
    packages: iocs.packages.length,
    hashes: iocs.hashes.length,
    markers: iocs.markers.length,
    files: iocs.files.length
  };
}

module.exports = { loadYAMLIOCs, getIOCStats };