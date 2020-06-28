FROM ubuntu:latest

RUN apt-get update && apt-get install -y wget gcc vim nano
COPY ttyd_linux.x86_64 /opt/ttyd
#RUN ["chmod", "+x", "/opt/ttyd"]
RUN chmod +x /opt/ttyd

RUN chmod 777 /bin/sh
RUN useradd --create-home --shell /bin/bash user
USER user

ENTRYPOINT ["/opt/ttyd", "-p", "8081", "bash"]
