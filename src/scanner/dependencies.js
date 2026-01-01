const fs = require('fs');
const path = require('path');
const { loadCachedIOCs } = require('../ioc/updater.js');

async function scanDependencies(targetPath) {
  const threats = [];
  const nodeModulesPath = path.join(targetPath, 'node_modules');
  const iocs = loadCachedIOCs();

  if (!fs.existsSync(nodeModulesPath)) {
    return threats;
  }

  const packages = listPackages(nodeModulesPath);

  for (const pkg of packages) {
    // Verifie si package connu malveillant (IOCs caches)
    const maliciousPkg = iocs.packages.find(p => p.name === pkg.name);
    if (maliciousPkg) {
      threats.push({
        type: 'known_malicious_package',
        severity: 'CRITICAL',
        message: `Package malveillant connu: ${pkg.name} (source: ${maliciousPkg.source})`,
        file: `node_modules/${pkg.name}`
      });
      continue;
    }

    // Verifie les fichiers suspects (IOCs caches)
    for (const suspFile of iocs.files || []) {
      const filePath = path.join(pkg.path, suspFile);
      if (fs.existsSync(filePath)) {
        threats.push({
          type: 'suspicious_file',
          severity: 'CRITICAL',
          message: `Fichier Shai-Hulud "${suspFile}" dans ${pkg.name}`,
          file: `node_modules/${pkg.name}/${suspFile}`
        });
      }
    }

    // Verifie les marqueurs dans package.json
    const pkgJsonPath = path.join(pkg.path, 'package.json');
    if (fs.existsSync(pkgJsonPath)) {
      const pkgContent = fs.readFileSync(pkgJsonPath, 'utf8');
      const pkgJson = JSON.parse(pkgContent);
      const scripts = pkgJson.scripts || {};

      // Verifie les marqueurs Shai-Hulud
      for (const marker of iocs.markers || []) {
        if (pkgContent.includes(marker)) {
          threats.push({
            type: 'shai_hulud_marker',
            severity: 'CRITICAL',
            message: `Marqueur "${marker}" detecte dans ${pkg.name}`,
            file: `node_modules/${pkg.name}/package.json`
          });
        }
      }

      // Verifie les lifecycle scripts
      if (scripts.preinstall || scripts.postinstall) {
        threats.push({
          type: 'lifecycle_script_dependency',
          severity: 'MEDIUM',
          message: `Dependance "${pkg.name}" a un script ${scripts.preinstall ? 'preinstall' : 'postinstall'}`,
          file: `node_modules/${pkg.name}/package.json`
        });
      }
    }
  }

  return threats;
}

function listPackages(nodeModulesPath) {
  const packages = [];
  const items = fs.readdirSync(nodeModulesPath);

  for (const item of items) {
    if (item.startsWith('.')) continue;

    const itemPath = path.join(nodeModulesPath, item);
    const stat = fs.statSync(itemPath);

    if (!stat.isDirectory()) continue;

    if (item.startsWith('@')) {
      const scopedItems = fs.readdirSync(itemPath);
      for (const scopedItem of scopedItems) {
        const scopedPath = path.join(itemPath, scopedItem);
        if (fs.statSync(scopedPath).isDirectory()) {
          packages.push({
            name: `${item}/${scopedItem}`,
            path: scopedPath
          });
        }
      }
    } else {
      packages.push({
        name: item,
        path: itemPath
      });
    }
  }

  return packages;
}

module.exports = { scanDependencies };