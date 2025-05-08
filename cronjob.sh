#! /bin/bash

# cron command to execute this script every 2 hours
# 0 */2 * * * /root/free-proxy-list/cronjob.sh

cd /root/free-proxy-list

start_time=$(date +%s)
node detectProxies.js detectProxies
end_time=$(date +%s)
echo "detectProxies.js took $((end_time - start_time)) seconds"

start_time=$(date +%s)
/bin/bash gitPush.sh
end_time=$(date +%s)
echo "gitPush.sh took $((end_time - start_time)) seconds"

