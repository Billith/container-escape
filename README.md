* [Architecture](#architecture)
* [Recommended hardware requirements](#recommended-hardware-requirements)
* [Recommended software](#recommended-software)
* [Installation](#installation)

Architecture
===
![arch](./images/sandbox-escape.png)

Recommended hardware requirements
===
* 8 VCPUs
* 8GB RAM
* 64GB disk

Recommended software
===
Project tested on:
* Ubuntu Server 18.04.4 LTS
* Docker version 19.03.8, build afacb8b7f0
* nginx version: nginx/1.14.0 (Ubuntu)
* Python 3.6.9

Installation
===========
* clone project
  ```bash
  cd /opt
  sudo git clone https://github.com/Billith/container-escape.git
  ```
  * install pip (on Ubuntu python3-pip package)
  * setup virtualenv (optional, to separate python environment)
    ```bash
    sudo pip3 install virtualenv
    cd /opt/container-escape
    sudo virtualenv venv
    sudo chown -R user:user venv/
    . ./venv/bin/activate
    pip install -r requirements.txt
    deactivate
    ```
* install and setup nginx
  * `/etc/nginx/nginx.conf`
    ```
    user www-data;
    worker_processes auto;
    pid /run/nginx.pid;
    include /etc/nginx/modules-enabled/*.conf;
    
    events {
        worker_connections 768;
    }
    
    http {
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        ssl_prefer_server_ciphers on;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        gzip on;
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*.conf;
    }
    ```
  * `/etc/nginx/sites-enabled/container-escape.conf`
    ```
    server {
        listen 80;
        include /etc/nginx/sites-enabled/containers/*;
        
        location / {
            proxy_pass http://127.0.0.1:5000/;
            proxy_set_header X-Real-IP $remote_addr;
        }
    }
    ```
  * `sudo mkdir /etc/nginx/sites-enabled/containers/`
  * restart service
    ```bash
    sudo systemctl restart nginx
    ```
* install docker (https://docs.docker.com/engine/install/ubuntu/)
* systemd service (optional)
  * `/etc/systemd/system/container-escape.service`
    ```
    [Unit]
    Description=Container Escape project service
    
    [Service]
    Type=simple
    ExecStart=/opt/container-escape/venv/bin/python /opt/container-escape/src/main.py
    WorkingDirectory=/opt/container-escape/src/
    
    [Install]
    WantedBy=multi-user.target
    ```
  * start service
    ```bash
    sudo systemctl enable --now container-escape
    ```
