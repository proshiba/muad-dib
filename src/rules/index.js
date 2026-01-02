const RULES = {
  // AST detections
  sensitive_string: {
    id: 'MUADDIB-AST-001',
    name: 'Sensitive String Reference',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Reference a un chemin ou identifiant sensible (.npmrc, .ssh, tokens)',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'
    ],
    mitre: 'T1552.001'
  },
  env_access: {
    id: 'MUADDIB-AST-002',
    name: 'Sensitive Environment Variable Access',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Acces a une variable d\'environnement sensible (GITHUB_TOKEN, NPM_TOKEN, AWS_*)',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions'
    ],
    mitre: 'T1552.001'
  },
  dangerous_call_exec: {
    id: 'MUADDIB-AST-003',
    name: 'Dangerous Function Call',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Appel a une fonction dangereuse (exec, spawn, eval, Function)',
    references: [
      'https://owasp.org/www-community/attacks/Command_Injection'
    ],
    mitre: 'T1059'
  },
  dangerous_call_eval: {
    id: 'MUADDIB-AST-004',
    name: 'Eval Usage',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Utilisation de eval() ou new Function() - execution de code dynamique',
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval#never_use_eval!'
    ],
    mitre: 'T1059.007'
  },

  // Shell detections
  curl_exec: {
    id: 'MUADDIB-SHELL-001',
    name: 'Remote Code Execution via Curl',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Telecharge et execute du code distant via curl | sh',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1105'
  },
  reverse_shell: {
    id: 'MUADDIB-SHELL-002',
    name: 'Reverse Shell',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Tentative de connexion reverse shell',
    references: [
      'https://attack.mitre.org/techniques/T1059/004/'
    ],
    mitre: 'T1059.004'
  },
  home_deletion: {
    id: 'MUADDIB-SHELL-003',
    name: 'Dead Man\'s Switch',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Suppression du repertoire home - dead man\'s switch de Shai-Hulud',
    references: [
      'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'
    ],
    mitre: 'T1485'
  },

  // Package detections
  lifecycle_script: {
    id: 'MUADDIB-PKG-001',
    name: 'Suspicious Lifecycle Script',
    severity: 'MEDIUM',
    confidence: 'medium',
    description: 'Script preinstall/postinstall suspect dans package.json',
    references: [
      'https://blog.npmjs.org/post/141577284765/kik-left-pad-and-npm'
    ],
    mitre: 'T1195.002'
  },

  // Obfuscation detections
  obfuscation_detected: {
    id: 'MUADDIB-OBF-001',
    name: 'Code Obfuscation Detected',
    severity: 'HIGH',
    confidence: 'medium',
    description: 'Code fortement obfusque detecte - probablement malveillant',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1027'
  },

  // Dependency detections
  known_malicious_package: {
    id: 'MUADDIB-DEP-001',
    name: 'Known Malicious Package',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Package present dans la base IOC de packages malveillants connus',
    references: [
      'https://socket.dev/npm/issue'
    ],
    mitre: 'T1195.002'
  },
  suspicious_file: {
    id: 'MUADDIB-DEP-002',
    name: 'Suspicious File in Dependency',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Fichier suspect detecte dans une dependance (setup_bun.js, etc.)',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1195.002'
  },
  shai_hulud_marker: {
    id: 'MUADDIB-DEP-003',
    name: 'Shai-Hulud Marker Detected',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Marqueur Shai-Hulud detecte dans le code',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm',
      'https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack'
    ],
    mitre: 'T1195.002'
  },
  lifecycle_script_dependency: {
    id: 'MUADDIB-DEP-004',
    name: 'Lifecycle Script in Dependency',
    severity: 'MEDIUM',
    confidence: 'low',
    description: 'Une dependance a un script preinstall/postinstall',
    references: [
      'https://docs.npmjs.com/cli/v9/using-npm/scripts#life-cycle-scripts'
    ],
    mitre: 'T1195.002'
  },

  // Hash detections
  known_malicious_hash: {
    id: 'MUADDIB-HASH-001',
    name: 'Known Malicious File Hash',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Hash SHA256 correspond a un fichier malveillant connu',
    references: [
      'https://www.virustotal.com'
    ],
    mitre: 'T1195.002'
  },

  // Dataflow detections
  suspicious_dataflow: {
    id: 'MUADDIB-FLOW-001',
    name: 'Suspicious Data Flow',
    severity: 'CRITICAL',
    confidence: 'high',
    description: 'Flux de donnees suspect: lecture de credentials puis envoi reseau',
    references: [
      'https://blog.phylum.io/shai-hulud-npm-worm'
    ],
    mitre: 'T1041'
  },

  typosquat_detected: {
    id: 'MUADDIB-TYPO-001',
    name: 'Typosquatting Detected',
    severity: 'HIGH',
    confidence: 'high',
    description: 'Package avec un nom tres similaire a un package populaire. Possible typosquatting.',
    references: [
      'https://blog.npmjs.org/post/163723642530/crossenv-malware-on-the-npm-registry',
      'https://snyk.io/blog/typosquatting-attacks/'
    ],
    mitre: 'T1195.002'
  },
};

function getRule(type) {
  return RULES[type] || {
    id: 'MUADDIB-UNK-001',
    name: 'Unknown Threat',
    severity: 'MEDIUM',
    confidence: 'low',
    description: 'Menace non categorisee',
    references: [],
    mitre: null
  };
}

module.exports = { RULES, getRule };