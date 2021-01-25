# cf-remote

## Requirements

cf-remote requires python 3.6 or greater.

## Installation

Install with pip3:

```
$ pip3 install cf-remote
```

## Examples

### See information about remote host

The `info` command can be used to check basic information about a system.

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
cf-remote install --hub 34.247.181.100 --bootstrap 172.31.44.146 --demo

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

### Specify an SSH key

If you have more than one key in `~/.ssh` you may need to specify which key `cf-remote` is to use.

```
$ export CF_REMOTE_SSH_KEY="~/.ssh/id_rsa.pub"
```

## Contribute

Feel free to open pull requests to expand this documentation, add features or fix problems.
You can also pick up an existing task or file an issue in [our bug tracker](https://tracker.mender.io/issues/?filter=11711).
