#!/bin/bash

set -o pipefail

run_command() {
  # $1: command to run
  # $2: variable name to store in / output
  # $3: custom error message (optional)
  result="$(bash -c "$1" 2>&1 | sed -e ':a' -e 'N' -e '$!ba' -e 's/\n/\\n/g' | sed -e 's/\"/\\"/g')"
  status=$?
  if [ "$status" -eq "0" ]; then
    echo "NTD_$2=\"$result\"" 
  else		
    echo "NTD_$2_CMD=\"$1\""
    # custom output result
    if [ "$#" -eq "3" ]; then	
      echo "NTD_$2_ERROR=\"$3\""
    else	
      echo "NTD_$2_ERROR=\"$result\""
    fi
  fi	
}

run_command "uname" "UNAME"
run_command "uname -m" "ARCH"
run_command "cat /etc/os-release" "OS_RELEASE"
run_command "cat /etc/redhat-release" "REDHAT_RELEASE"

# cf-agent

cfagent_path=$(command -v cf-agent)

if ! [ $? -eq "0" ]; then
  cfagent_path=$(command -v /var/cfengine/bin/cf-agent)

  if   ! [ $? -eq "0" ]; then
    cfagent_path="cf-agent"
  fi
fi

run_command "command -v $cfagent_path" "CFAGENT_PATH" "Cannot find cf-agent"
run_command "$cfagent_path --version" "CFAGENT_VERSION" 
run_command "cat /var/cfengine/policy_server.dat" "POLICY_SERVER"

# packages

run_command "echo $UID" "UID"
run_command "command -v dpkg" "DPKG" "Cannot find dpkg"
run_command "command -v rpm" "RPM" "Cannot find rpm"
run_command "command -v yum" "YUM" "Cannot find yum"
run_command "command -v apt" "APT" "Cannot find apt"
run_command "command -v pkg" "PKG" "Cannot find pkg"
run_command "command -v zypper" "ZYPPER" "Cannot find zypper"

