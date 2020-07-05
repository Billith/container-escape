FROM docker:dind

COPY ./mount_vuln.tar /opt
COPY ./create_disk.sh /root/create_disk.sh
RUN apk add bash && chmod +x /root/create_disk.sh

ENTRYPOINT ["dockerd-entrypoint.sh"]
