# Cloudflare x MongoDB
Repositori ini dibuat untuk melakukan export data Cloudflare security event ke mongodb, yang dimana ini menjadi solusi dari limitasi dari plan yang dipilih pada cloudflare 

## Install dependency
```
pip3 install -r requirement.txt
```

## Cronjob
Set up a cronjob with `crontab -e` and set the execution time, in this example it will be executed every 23:59
```
59 23 * * * cd /home/user/cloudflare-security-event/ && /usr/bin/python3 cloudflare-events.py >> /var/log/cloudflare-events.log 2>&1
```