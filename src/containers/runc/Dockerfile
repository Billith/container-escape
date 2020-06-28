FROM docker:dind-rootless

COPY runc-1.0.0-rc6-vulnerable /usr/local/bin/runc
COPY ./runc_vuln.tar /opt
USER root
RUN chmod 777 /usr/local/bin/runc
USER rootless

ENTRYPOINT ["dockerd-entrypoint.sh"]
