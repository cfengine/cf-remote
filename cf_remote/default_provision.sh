#!/usr/bin/env bash
set -e

# some boxes miss these files
sudo mkdir -p /root/.ssh
sudo chmod 700 /root/.ssh
sudo touch /root/.ssh/authorized_keys
sudo chmod 600 /root/.ssh/authorized_keys

if grep -q "centos:7" /etc/*release; then
    echo "CentOS 7 EOL detected. Switching to Vault mirrors..."
    sudo sed -i 's/mirrorlist.centos.org/vault.centos.org/g' /etc/yum.repos.d/CentOS-*.repo
    sudo sed -i 's/#baseurl=http:\/\/mirror.centos.org/baseurl=http:\/\/vault.centos.org/g' /etc/yum.repos.d/CentOS-*.repo
    sudo sed -i 's/^mirrorlist=/#mirrorlist=/g' /etc/yum.repos.d/CentOS-*.repo
    sudo yum clean all
fi

echo "Successfully provisioned VM"
