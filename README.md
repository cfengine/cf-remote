# cf-remote

`cf-remote` is a tool to deploy CFEngine.
It works by contacting remote hosts with SSH and using `ssh` / `scp` to copy files and run commands.
Commands for provisioning hosts in the cloud (AWS or GCP) are also available.

## Requirements

cf-remote requires python 3.6 or greater.
SSH must be configured in such a way that cf-remote can login without a password.
An sftp server for transferring files on UNIX hosts. e.g. openssh-sftp-server for debian-based distributions.

## Installation

Install with pip3:

```
$ pip3 install cf-remote
```

## Examples

### See information about remote host

The `info` command can be used to check basic information about a system.
The --hosts/-H option accepts [user@]hostname[:port] for the hostname.

```
$ cf-remote info -H 34.241.203.218

ubuntu@34.241.203.218
OS            : ubuntu (debian)
Architecture  : x86_64
CFEngine      : 3.12.1
Policy server : 172.31.42.192
Binaries      : dpkg, apt
```

(You must have ssh access).

### Installing and bootstrapping CFEngine Enterprise Hub

The `install` command can automatically download and install packages as well as bootstrap both hubs and clients.

```
$ cf-remote install --hub 34.247.181.100 --bootstrap 172.31.44.146 --demo

ubuntu@34.247.181.100
OS            : ubuntu (debian)
Architecture  : x86_64
CFEngine      : Not installed
Policy server : None
Binaries      : dpkg, apt

Package already downloaded: '/Users/olehermanse/.cfengine/cf-remote/packages/cfengine-nova-hub_3.12.1-1_amd64.deb'
Copying: '/Users/olehermanse/.cfengine/cf-remote/packages/cfengine-nova-hub_3.12.1-1_amd64.deb' to '34.247.181.100'
Installing: 'cfengine-nova-hub_3.12.1-1_amd64.deb' on '34.247.181.100'
CFEngine 3.12.1 was successfully installed on '34.247.181.100'
Bootstrapping: '34.247.181.100' -> '172.31.44.146'
Bootstrap successful: '34.247.181.100' -> '172.31.44.146'
Transferring def.json to hub: '34.247.181.100'
Copying: '/Users/olehermanse/.cfengine/cf-remote/json/def.json' to '34.247.181.100'
Triggering an agent run on: '34.247.181.100'
Disabling password change on hub: '34.247.181.100'
Triggering an agent run on: '34.247.181.100'
Your demo hub is ready: https://34.247.181.100/ (Username: admin, Password: password)
```

Note that this demo setup (`--demo`) is notoriously insecure.
It has default passwords and open access controls.
Don't use it in a production environment.

### Spawning instances in AWS EC2

`cf-remote spawn` can create cloud instances on demand, for example in AWS EC2, but you'll have to add some credentials and settings:

```
$ cf-remote spawn --init-config
Config file /home/olehermanse/.cfengine/cf-remote/cloud_config.json created, please complete the configuration in it.
$ cat /home/olehermanse/.cfengine/cf-remote/cloud_config.json
{
  "aws": {
    "key": "TBD",
    "secret": "TBD",
    "key_pair": "TBD",
    "security_groups": [
      "TBD"
    ],
    "region": "OPTIONAL (DEFAULT: eu-west-1)"
  },
  "gcp": {
    "project_id": "TBD",
    "service_account_id": "TBD",
    "key_path": "TBD",
    "region": "OPTIONAL (DEFAULT: europe-west1-b)"
  }
}
```

You can skip the `gcp` values if you will only be using AWS. After filling out those 4, it should just work:

```
$ cf-remote spawn --count 1 --platform ubuntu-20-04-x64 --role hub --name hub
Spawning VMs....DONE
Waiting for VMs to get IP addresses..........DONE
Details about the spawned VMs can be found in /home/olehermanse/.cfengine/cf-remote/cloud_state.json
```

You can now install nightlies, and use the ```--demo``` to make testing easier (**Not** secure for production use).
Referring to the group names set by spawn, makes the commands a lot shorter and easier to script:

```
$ cf-remote --version master install --hub hub --bootstrap hub --demo

ubuntu@52.214.209.170
OS            : ubuntu (debian)
Architecture  : x86_64
CFEngine      : Not installed
Policy server : None
Binaries      : dpkg, apt

Downloading package: '/home/olehermanse/.cfengine/cf-remote/packages/cfengine-nova-hub_3.18.0a.a24173342~12762.ubuntu18_amd64.deb'
Copying: '/home/olehermanse/.cfengine/cf-remote/packages/cfengine-nova-hub_3.18.0a.a24173342~12762.ubuntu18_amd64.deb' to 'ubuntu@52.214.209.170'
Installing: 'cfengine-nova-hub_3.18.0a.a24173342~12762.ubuntu18_amd64.deb' on 'ubuntu@52.214.209.170'
CFEngine 3.18.0a.a24173342 (Enterprise) was successfully installed on 'ubuntu@52.214.209.170'
Bootstrapping: '52.214.209.170' -> '172.31.5.84'
Bootstrap successful: '52.214.209.170' -> '172.31.5.84'
Transferring def.json to hub: 'ubuntu@52.214.209.170'
Copying: '/home/olehermanse/.cfengine/cf-remote/json/def.json' to 'ubuntu@52.214.209.170'
Triggering an agent run on: '52.214.209.170'
Disabling password change on hub: 'ubuntu@52.214.209.170'
Triggering an agent run on: '52.214.209.170'
Your demo hub is ready: https://52.214.209.170/ (Username: admin, Password: password)
```

Mission portal will be available at that IP, using the username and password from the last log message.

When you are done, you can decommision your spawned instance(s) using:

```
$ cf-remote destroy --all
Destroying all hosts
```

### Deploying a version of masterfiles you're working on locally

The `deploy` command allows you to deploy your local checkout of masterfiles, to test policy while working on it:

```
$ cf-remote deploy --hub hub ~/code/northern.tech/cfengine/masterfiles

ubuntu@18.202.238.128
OS            : ubuntu (debian)
Architecture  : x86_64
CFEngine      : 3.18.0a.a24173342 (Enterprise)
Policy server : None
Binaries      : dpkg, apt

Copying: '/home/olehermanse/.cfengine/cf-remote/masterfiles.tgz' to 'ubuntu@18.202.238.128'
Running: 'systemctl stop cfengine3 && rm -rf /var/cfengine/masterfiles && mv masterfiles /var/cfengine/masterfiles && systemctl start cfengine3 && cf-agent -Kf update.cf && cf-agent -K'
$
```

### Specify an SSH key

If you have more than one key in `~/.ssh` you may need to specify which key `cf-remote` is to use.

```
$ export CF_REMOTE_SSH_KEY="~/.ssh/id_rsa.pub"
```

### Working on the local host

`cf-remote` can work on the local host when the target host is `localhost`. In this case, it executes commands locally without connecting over SSH.

```
$ cf-remote info -H localhost

ubuntu@localhost
OS            : ubuntu (debian)
Architecture  : x86_64
CFEngine      : 3.12.1
Policy server : 172.31.42.192
Binaries      : dpkg, apt
```

When performing actions locally, `cf-remote` may require your password to run commands with `sudo`:

```
$ cf-remote install --clients localhost
ubuntu@localhost
OS            : debian
Architecture  : x86_64
CFEngine      : Not installed
Policy server :
Binaries      : dpkg, apt
Installing: '/home/ubuntu/.cfengine/cf-remote/packages/cfengine-nova_3.15.3-1.debian10_amd64.deb' on 'localhost'
[sudo] password for ubuntu:
CFEngine 3.15.3 (Enterprise) was successfully installed on 'localhost'
```

## Contribute

Feel free to open pull requests to expand this documentation, add features or fix problems.
You can also pick up an existing task or file an issue in [our bug tracker](https://northerntech.atlassian.net/issues/?filter=10068).

## Development

To install `cf-remote` so that it reflects any changes in this source directory use:

```
$ pip install --editable .
```

## cloud_data.py tips

In order to find AWS images for a particular owner to work on cloud_data.py name_pattern list the names for an owner with the following `aws` command:

aws ec2 describe-images --region us-east-2 --owners 801119661308 --query 'Images[*].[Name]' --output text
