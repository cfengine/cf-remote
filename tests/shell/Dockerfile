FROM debian:12-slim

# openssh-server depends on dbus and systemd which is a lot, so use dropbear instead
RUN apt update -y && apt install -y dropbear openssh-sftp-server

# setup no password login via ssh for root
RUN sed -ie 's/^root:[^:]*:/root::/' /etc/shadow

# run dropbear sshd in foreground (-F) and allow blank password logins (-B)
CMD [ "dropbear", "-FB" ]
