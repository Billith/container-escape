#!/bin/bash

RNAME='/root/'$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)'.iso'
fallocate -l 64K $RNAME
mkfs.ext4 -j $RNAME
chmod 766 $RNAME
mkdir /mnt/flag
mount $RNAME /mnt/flag -o loop
if [ $? -ne 0 ]; then
    NUM=$(($(ls /dev | grep loop | tr -d loop | sort -n | tail -n 1) + 1))
    mknod -m666 /dev/loop$NUM b 7 0 && chown root:disk /dev/loop$NUM
    losetup /dev/loop$NUM $RNAME
    mount $RNAME /mnt/flag -o loop
fi
df -h | grep /mnt/flag | cut -f1 -d " " > /root/loop.txt
if [ $(cat /root/loop.txt | wc -c) -ne 0 ]; then
    echo -e '#!/bin/bash \ncd $(dirname $0) \ntouch VICTORY' > /mnt/flag/RUN_ME_TO_WIN.sh
    chmod +x /mnt/flag/RUN_ME_TO_WIN.sh
fi