# Indempotent VM spawning config



## Core concepts:

- Fully reproducible and sharable cfengine testing environment
- Should work for dev environment: support for package install and scripts
- Atomic config: either all vms created or none. No in-between states.
- Top-down run order
- VMs bound to config that generated them. Should not manually interfer: VMs should not be destroyed manually and the config should not be modified while VMs are running.
- Should provide abstraction of provider (aws, vagrant, static)


## Example:

```
machines:
  - ubuntu-vm:
      provider: aws # if we want to force provider
      count: 1 # ignore if provider is "static"

      aws:
        image: ubuntu-24

      vagrant:
        image: ubuntu/focal64
        memory: 1024
        cpus: 2

      static: 
        hosts: [ ubuntu@8.8.8.8, ubuntu@1.1.1.1 ]

packages:
  - cfengine-master:
      package: cfengine
      version: master
      bootstrap: myhub # myhub count must be 1

  - git-latest:
      package: git
      version: latest

hubs:
  - myhub:
      from: ubuntu-vm
      install: [ cfengine-master, git-latest ]
      scripts: [ ./provision.sh ]

clients:
  - myclient: 
      from: ubuntu-vm
      install: [ cfengine-master ]
```
