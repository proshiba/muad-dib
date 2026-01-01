const fs = require('fs');
const path = require('path');
const { run } = require('./index.js');

let debounceTimer = null;

function watch(targetPath) {
  console.log(`[MUADDIB] Surveillance de ${targetPath}\n`);
  console.log('[INFO] Ctrl+C pour arreter\n');

  // Scan initial
  run(targetPath, { json: false });

  // Surveille les changements
  const watchPaths = [
    path.join(targetPath, 'package.json'),
    path.join(targetPath, 'package-lock.json'),
    path.join(targetPath, 'node_modules')
  ];

  for (const watchPath of watchPaths) {
    if (fs.existsSync(watchPath)) {
      fs.watch(watchPath, { recursive: true }, (eventType, filename) => {
        if (debounceTimer) clearTimeout(debounceTimer);
        
        debounceTimer = setTimeout(() => {
          console.log(`\n[CHANGE] ${filename} modifie`);
          console.log('[MUADDIB] Re-scan...\n');
          run(targetPath, { json: false });
        }, 1000);
      });
      console.log(`[WATCH] ${watchPath}`);
    }
  }
}

module.exports = { watch };