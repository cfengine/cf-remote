# Idempotent VM spawning config

## Idempotency:
The user defines a desired state in the form of a config in yaml, and cf-remote makes it a reality.
If run against an existing environment, it detects changes and 'repairs' the current state using the configuration.

## Example

```yml
templates:
  ubuntu-vm:
    provider:
      name: aws
      aws:
        image: ubuntu-24

  centos7:
    provider:
      name: vagrant
      vagrant:
        box: generic/centos7

groups:
  - myhub:
      role: hub
      count: 1
      spawn-config: ubuntu-vm
      cfengine: 
        version: 3.24.3 
      scripts: [ ./script.sh ]

  - myclient:
      role: client
      count: 3
      spawn-config: centos7
      cfengine: 
        version: 3.24.3
        bootstrap: myhub

  - other:
      role: client
      spawn-config:
        hosts: [ ubuntu@1.1.1.1 ]
      cfengine:
        version: 3.24.3
        bootstrap: myhub
```

### Spawning

```bash
cf-remote up config.yaml
```

Example output. myclient is already spawned from a previous run. 
```
Checking current state...
Checking 'myhub'... Changes detected. Enabling repair
  Spawning: 'ubuntu-24' on 'aws' provider... OK
  Installing: 'cfengine-nova-hub_3.27.0-1.ubuntu24_amd64.deb' on 'ubuntu@34.244.25.232'... OK
  Running: './script.sh' on 'ubuntu@34.244.25.232'... OK
Checking 'myclient'... No Changes detected. OK
Checking 'other'... Changes detected. Enabling repair
  Hosts: adding 'ubuntu@1.1.1.1' to 'other'... OK
  Installing: 'cfengine-nova-client_3.27.0-1.ubuntu24_amd64.deb' on 'ubuntu@1.1.1.1'... OK
  Bootstrapping: '1.1.1.1' -> '172.31.23.220'... OK
Details about the current state can be found in /home/user/.cfengine/cf-remote/cloud_state.json
```

### Destroying

```bash
cf-remote destroy config.yaml
```

# Future features

- inlining (being able to split config in smaller subtrees)