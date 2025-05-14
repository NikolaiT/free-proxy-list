#! /bin/bash

# cron command to execute this script every 2 hours
# 0 */2 * * * /root/free-proxy-list/cronjob.sh

cd /root/free-proxy-list

# Create log file if it doesn't exist
touch cron.log

# Log start of script
echo "[$(date)] Starting proxy detection cronjob" >> cron.log

start_time=$(date +%s)
node detectProxies.js detectProxies >> cron.log 2>&1
end_time=$(date +%s)
echo "[$(date)] detectProxies.js took $((end_time - start_time)) seconds" >> cron.log

node detectProxies.js writeWorkingProxiesToFiles >> cron.log 2>&1

start_time=$(date +%s)
/bin/bash gitPush.sh >> cron.log 2>&1
end_time=$(date +%s)
echo "[$(date)] gitPush.sh took $((end_time - start_time)) seconds" >> cron.log

# Log completion
echo "[$(date)] Completed proxy detection cronjob" >> cron.log
