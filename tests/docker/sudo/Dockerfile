FROM debian:12-slim

# openssh-server depends on dbus and systemd which is a lot, so use dropbear instead
RUN apt update -y && apt install -y dropbear openssh-sftp-server sudo

# 'cftest' may sudo, but has to type a password to do it
RUN useradd -m -s /bin/bash cftest && echo 'cftest:cftestpw' | chpasswd
RUN echo 'cftest ALL=(ALL:ALL) ALL' > /etc/sudoers.d/cftest && chmod 440 /etc/sudoers.d/cftest

# 'cfnopass' may sudo without one, to check that we don't send a password
# where none is wanted (it would end up on the standard input of the command
# we are running instead)
RUN useradd -m -s /bin/bash cfnopass
RUN echo 'cfnopass ALL=(ALL:ALL) NOPASSWD: ALL' > /etc/sudoers.d/cfnopass \
 && chmod 440 /etc/sudoers.d/cfnopass

# Log in over SSH with a key, so that the account password is only ever used
# for sudo, which is what we are testing
COPY id_test.pub /tmp/id_test.pub
RUN for u in cftest cfnopass; do \
      install -d -m 700 -o $u -g $u /home/$u/.ssh && \
      install -m 600 -o $u -g $u /tmp/id_test.pub /home/$u/.ssh/authorized_keys; \
    done && rm /tmp/id_test.pub

# run dropbear sshd in foreground (-F), log to stderr (-E), create host keys (-R)
CMD [ "dropbear", "-F", "-E", "-R" ]
