#! /bin/bash

# cron command to execute this script every 2 hours
# 0 */2 * * * /root/free-proxy-list/cronjob.sh

# Set PATH to include common Node.js installation locations
export PATH="/root/.nvm/versions/node/v23.11.0/bin:/usr/local/bin:/usr/bin:/bin:/opt/homebrew/bin:$PATH"

# Find Node.js executable
NODE_CMD="node"
if ! command -v node &> /dev/null; then
    # Try common Node.js installation paths, starting with the known NVM path
    for path in "/root/.nvm/versions/node/v23.11.0/bin/node" "/usr/local/bin/node" "/usr/bin/node" "/opt/homebrew/bin/node" "/home/ubuntu/.nvm/versions/node/*/bin/node"; do
        if [ -f "$path" ]; then
            NODE_CMD="$path"
            break
        fi
    done
fi

cd /root/free-proxy-list

# Create log file if it doesn't exist
touch cron.log

# Log start of script
echo "[$(date)] Starting proxy detection cronjob" | tee -a cron.log
echo "[$(date)] Using Node.js command: $NODE_CMD" | tee -a cron.log
echo "[$(date)] PATH: $PATH" | tee -a cron.log

start_time=$(date +%s)
echo "[$(date)] Starting detectProxies command" | tee -a cron.log
if $NODE_CMD detectProxies.js detectProxies 2>&1 | tee -a cron.log; then
    end_time=$(date +%s)
    echo "[$(date)] detectProxies.js completed successfully in $((end_time - start_time)) seconds" | tee -a cron.log
    
    start_time=$(date +%s)
    echo "[$(date)] Starting writeWorkingProxiesToFiles command" | tee -a cron.log
    if $NODE_CMD detectProxies.js writeWorkingProxiesToFiles 2>&1 | tee -a cron.log; then
        end_time=$(date +%s)
        echo "[$(date)] writeWorkingProxiesToFiles completed successfully in $((end_time - start_time)) seconds" | tee -a cron.log
    else
        echo "[$(date)] ERROR: writeWorkingProxiesToFiles failed" | tee -a cron.log
        exit 1
    fi
else
    echo "[$(date)] ERROR: detectProxies failed" | tee -a cron.log
    exit 1
fi

start_time=$(date +%s)
echo "[$(date)] Starting git push" | tee -a cron.log
if /bin/bash gitPush.sh 2>&1 | tee -a cron.log; then
    end_time=$(date +%s)
    echo "[$(date)] git push completed successfully in $((end_time - start_time)) seconds" | tee -a cron.log
else
    echo "[$(date)] ERROR: git push failed" | tee -a cron.log
    exit 1
fi

# Log completion
echo "[$(date)] Completed proxy detection cronjob" | tee -a cron.log
