'use strict';

const {
  SENSITIVE_STRINGS,
  AI_AGENT_DANGEROUS_FLAGS,
  SAFE_STRINGS,
  SUSPICIOUS_DOMAINS_HIGH,
  SUSPICIOUS_DOMAINS_MEDIUM,
  BLOCKCHAIN_RPC_ENDPOINTS,
  SOLANA_C2_METHODS,
  VARIATION_SELECTOR_CONSTS
} = require('./constants.js');

function handleLiteral(node, ctx) {
  if (typeof node.value === 'string') {
    // Ignore safe strings
    if (SAFE_STRINGS.some(s => node.value.includes(s))) {
      return;
    }

    for (const sensitive of SENSITIVE_STRINGS) {
      if (node.value.includes(sensitive)) {
        ctx.threats.push({
          type: 'sensitive_string',
          severity: 'HIGH',
          message: `Reference to "${sensitive}" detected.`,
          file: ctx.relFile
        });
      }
    }

    // Detect AI agent dangerous flags as string literals (MEDIUM signal only —
    // CRITICAL reserved for CallExpression context where flag is actually used in exec/spawn)
    for (const flag of AI_AGENT_DANGEROUS_FLAGS) {
      if (node.value === flag) {
        // Skip if already detected in a CallExpression context (avoid double-counting)
        const alreadyDetected = ctx.threats.some(t =>
          t.type === 'ai_agent_abuse' && t.severity === 'CRITICAL' && t.file === ctx.relFile
        );
        if (!alreadyDetected) {
          ctx.threats.push({
            type: 'ai_agent_abuse',
            severity: 'MEDIUM',
            message: `AI agent security bypass flag "${flag}" referenced in code — verify it is not used in exec/spawn invocations.`,
            file: ctx.relFile
          });
        }
      }
    }

    // Detect suspicious C2/exfiltration domains in string literals
    const lowerVal = node.value.toLowerCase();
    for (const domain of SUSPICIOUS_DOMAINS_HIGH) {
      if (lowerVal.includes(domain)) {
        ctx.threats.push({
          type: 'suspicious_domain',
          severity: 'HIGH',
          message: `Suspicious C2/exfiltration domain "${domain}" found in string literal.`,
          file: ctx.relFile
        });
        break;
      }
    }
    for (const domain of SUSPICIOUS_DOMAINS_MEDIUM) {
      if (lowerVal.includes(domain)) {
        ctx.threats.push({
          type: 'suspicious_domain',
          severity: 'MEDIUM',
          message: `Suspicious tunnel/proxy domain "${domain}" found in string literal.`,
          file: ctx.relFile
        });
        break;
      }
    }

    // Ollama LLM local: polymorphic engine indicator (PhantomRaven Wave 4)
    // Port 11434 is Ollama's default port. Legitimate packages don't call local LLMs.
    if (/(?:localhost|127\.0\.0\.1):11434/.test(node.value)) {
      ctx.threats.push({
        type: 'ollama_local_llm',
        severity: 'HIGH',
        message: `Reference to Ollama LLM API (${node.value.slice(0, 60)}) — polymorphic malware engine: uses local LLM to rewrite code and evade detection.`,
        file: ctx.relFile
      });
    }

    // Blockchain RPC endpoints — potential C2 channel (GlassWorm)
    for (const endpoint of BLOCKCHAIN_RPC_ENDPOINTS) {
      if (lowerVal.includes(endpoint)) {
        ctx.threats.push({
          type: 'blockchain_rpc_endpoint',
          severity: 'MEDIUM',
          message: `Hardcoded blockchain RPC endpoint "${endpoint}" — potential blockchain C2 channel.`,
          file: ctx.relFile
        });
        break;
      }
    }

    // Track Solana C2 method names in string literals (for compound detection)
    for (const method of SOLANA_C2_METHODS) {
      if (node.value === method || node.value.includes(method)) {
        ctx.hasSolanaC2Method = true;
        break;
      }
    }

    // Redis RCE via CONFIG SET — attacker sends raw Redis protocol to inject files into
    // sensitive paths (cron, SSH authorized_keys, PHP webshells). Pattern observed in
    // strapi-plugin-cron / strapi-plugin-events supply-chain attack.
    if (/CONFIG\s+SET\s+dir\s+/i.test(node.value)) {
      if (/\/var\/spool\/cron|\/etc\/cron|crontabs/i.test(node.value)) {
        ctx.threats.push({
          type: 'redis_rce_crontab',
          severity: 'CRITICAL',
          message: 'Redis RCE: CONFIG SET dir targets a cron path — exploits Redis to write cron entries for persistence.',
          file: ctx.relFile
        });
      } else if (/\/root\/\.ssh|\/home\/[^/\\]+\/\.ssh/i.test(node.value)) {
        ctx.threats.push({
          type: 'redis_rce_ssh_inject',
          severity: 'CRITICAL',
          message: 'Redis RCE: CONFIG SET dir targets SSH directory — exploits Redis to inject authorized_keys for backdoor access.',
          file: ctx.relFile
        });
      } else if (/\/var\/www|\/app\/public|\/srv\/http|\/usr\/share\/nginx|\/public\/uploads|\/static|\/assets|\/web\/|\/html\//i.test(node.value)) {
        ctx.threats.push({
          type: 'redis_rce_webshell',
          severity: 'CRITICAL',
          message: `Redis RCE: CONFIG SET dir targets web-accessible path "${node.value.substring(0, 80)}" — exploits Redis to write PHP webshell or other files.`,
          file: ctx.relFile
        });
      }
    }

    // Redis CONFIG SET dbfilename to sensitive filenames
    if (/CONFIG\s+SET\s+dbfilename\s+authorized_keys/i.test(node.value)) {
      ctx.threats.push({
        type: 'redis_rce_ssh_inject',
        severity: 'CRITICAL',
        message: 'Redis RCE: CONFIG SET dbfilename authorized_keys — injects SSH public key via Redis file write.',
        file: ctx.relFile
      });
    } else if (/CONFIG\s+SET\s+dbfilename\s+\S+\.php/i.test(node.value)) {
      ctx.threats.push({
        type: 'redis_rce_webshell',
        severity: 'CRITICAL',
        message: 'Redis RCE: CONFIG SET dbfilename to .php file — deploys PHP webshell via Redis database persistence.',
        file: ctx.relFile
      });
    }

    // PHP webshell code embedded in string literals
    if (/\<\?php\s+system\s*\(/.test(node.value) || /\<\?php[^>]{0,100}\$_(?:GET|POST|REQUEST)\s*\[/.test(node.value)) {
      ctx.threats.push({
        type: 'php_webshell_string',
        severity: 'CRITICAL',
        message: 'PHP webshell code in string literal: system() with user-controlled input — remote command execution via HTTP request.',
        file: ctx.relFile
      });
    }

    // Raw disk read: dd if=/dev/sdX or mknod block device creation
    // Used in container escape attacks to read raw disk blocks bypassing filesystem permissions
    if (/\bdd\s+if=\/dev\/[sh]d[a-z]\d*/i.test(node.value) || /\bdd\s+if=\/dev\/nvme\d/i.test(node.value)) {
      ctx.threats.push({
        type: 'raw_disk_read',
        severity: 'CRITICAL',
        message: 'Raw disk read via dd if=/dev/sdX — bypasses filesystem permissions to extract secrets from raw disk blocks.',
        file: ctx.relFile
      });
    }
    if (/\bmknod\s+\S+\s+b\s+\d+\s+\d+/.test(node.value)) {
      ctx.threats.push({
        type: 'raw_disk_read',
        severity: 'CRITICAL',
        message: 'Block device creation via mknod — creates raw disk access device for host data extraction from container.',
        file: ctx.relFile
      });
    }
  }

  // Track variation selector constants in numeric literals (GlassWorm decoder)
  if (typeof node.value === 'number') {
    if (VARIATION_SELECTOR_CONSTS.includes(node.value)) {
      ctx.hasVariationSelectorConst = true;
    }
  }
}


module.exports = { handleLiteral };
