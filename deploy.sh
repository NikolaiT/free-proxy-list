#!/bin/bash

# deploy the sources to the server with rsync
rsync -avz \
  --exclude-from=exclude.txt \
  -e "ssh -i /Users/nikolaitschacher/.ssh/honeypot" \
  . \
  root@78.47.63.161:/root/free-proxy-list
