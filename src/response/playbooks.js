const PLAYBOOKS = {
  lifecycle_script: 
    'Verifier le contenu du script. Desactiver avec "npm config set ignore-scripts true" si suspect.',
  
  curl_pipe_sh: 
    'CRITIQUE: Ne jamais executer. Inspecter l\'URL telechargee. Verifier si deja execute.',
  
  wget_pipe_sh:
    'CRITIQUE: Ne jamais executer. Inspecter l\'URL telechargee. Verifier si deja execute.',
  
  eval_usage:
    'Code dynamique detecte. Verifier la source des donnees evaluees. Risque d\'injection.',
  
  child_process:
    'Execution de commandes systeme. Verifier quelles commandes sont lancees.',
  
  child_process_import:
    'Module child_process importe. Verifier son utilisation dans le code.',
  
  npmrc_access:
    'Acces au fichier .npmrc detecte. Risque de vol de token npm. Regenerer le token.',
  
  npmrc_read:
    'Lecture du .npmrc. Regenerer immediatement: npm token revoke && npm login',
  
  github_token_access:
    'Acces au GITHUB_TOKEN. Verifier les permissions. Regenerer si compromis.',
  
  aws_credential_access:
    'Acces aux credentials AWS. Rotation immediate recommandee via AWS IAM.',
  
  sensitive_env_access:
    'Acces a des variables sensibles. Verifier l\'usage. Rotation des secrets recommandee.',
  
  base64_encoding:
    'Encodage base64 detecte. Souvent utilise pour obfusquer du code malveillant.',
  
  base64_decode:
    'Decodage base64 detecte. Verifier ce qui est decode et execute.',
  
  reverse_shell:
    'CRITIQUE: Reverse shell detecte. Machine potentiellement compromise. Isoler immediatement.',
  
  netcat_shell:
    'CRITIQUE: Shell netcat detecte. Machine potentiellement compromise. Isoler immediatement.',
  
  home_deletion:
    'CRITIQUE: Tentative de suppression du repertoire home. Dead man\'s switch probable.',
  
  shred_home:
    'CRITIQUE: Destruction de donnees detectee. Dead man\'s switch de Shai-Hulud.',
  
  curl_exfiltration:
    'Exfiltration de donnees via curl. Verifier les donnees envoyees et la destination.',
  
  ssh_access:
    'Acces aux cles SSH. Regenerer les cles si compromis: ssh-keygen -t ed25519',
  
  ssh_key_read:
    'Lecture des cles SSH. Regenerer immediatement toutes les cles.',
  
  github_api_call:
    'Appel a l\'API GitHub. Verifier le contexte. Peut etre legitime ou exfiltration.',
  
  exec_curl:
    'Execution de curl via child_process. Verifier l\'URL et les donnees.',
  
  exec_wget:
    'Execution de wget via child_process. Verifier l\'URL et les donnees.',
  
  wget_chmod_exec:
    'Telechargement et execution de binaire. Ne pas executer. Analyser le fichier.',

  known_malicious_package:
    'CRITIQUE: Supprimer immediatement. rm -rf node_modules && npm cache clean --force && npm install',

  lifecycle_script_dependency:
    'Verifier le contenu du script dans le package. Reinstaller avec --ignore-scripts si suspect.',

  suspicious_file:
    'Fichier typique de Shai-Hulud. Ne pas executer. Verifier le hash contre les IOCs connus.',

  obfuscation_detected:
    'Code volontairement obscurci. Analyser dans un environnement isole. Probable malware.',

  dangerous_call_eval:
    'Appel eval() detecte. Verifier la source des donnees. Risque d\'execution de code arbitraire.',

  dangerous_call_exec:
    'Execution de commande systeme. Verifier les arguments passes.',

  dangerous_call_spawn:
    'Spawn de processus detecte. Verifier la commande executee.',

  sensitive_string:
    'Reference a un chemin ou identifiant sensible. Verifier le contexte d\'utilisation.',

  env_access:
    'Acces a une variable d\'environnement sensible. Verifier si les donnees sont exfiltrees.',
};

function getPlaybook(threatType) {
  return PLAYBOOKS[threatType] || 'Analyser manuellement cette menace.';
}

module.exports = { getPlaybook, PLAYBOOKS };