# Cloudflare x MongoDB
This repository was created to export Cloudflare security event data to MongoDB, which is a workaround for the limitations of the selected plan in Cloudflare. 

## Install dependency
```
pip3 install -r requirement.txt
```

## Cronjob
Set up a cronjob with `crontab -e` and set the execution time, in this example it will be executed every 23:59
```
59 23 * * * cd /home/user/cloudflare-security-event/ && /usr/bin/python3 cloudflare-events.py >> /var/log/cloudflare-events.log 2>&1
```