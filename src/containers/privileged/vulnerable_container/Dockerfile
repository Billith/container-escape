FROM ubuntu:latest

COPY ttyd_linux.x86_64 /opt/ttyd
RUN ["chmod", "+x", "/opt/ttyd"]

ENTRYPOINT ["/opt/ttyd", "-p", "8081", "bash"]
