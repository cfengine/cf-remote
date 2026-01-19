from cf_remote.utils import CFRConfigValidationError

from pydantic import BaseModel, model_validator, ValidationError
from typing import Union, Literal, Optional, List, Self, Dict
from enum import Enum

from functools import reduce
from collections import defaultdict, deque

import os

from multiprocessing import Pool

import concurrent.futures

"""
What does cf-remote need to do:
1. spawn VMs, install cfengine
2. deploy masterfiles
3. show hosts
4. scp, ssh


For it, we need:
1. Save hosts in a state file (cloud_state.json)
2. Save previous config

How it works:
1. load previous config
2. compare
3. apply changes: schedule them in order (normal order)
"""


class NoExtra(BaseModel, extra="forbid"):
    pass


class Config(NoExtra):
    pass


class AWSConfig(Config):
    image: str
    size: str = "small"

    @model_validator(mode="after")
    def check_aws_config(self) -> Self:
        # 1. check if image exists
        # 2. check correct size
        return self


class VagrantConfig(Config):
    box: str

    @model_validator(mode="after")
    def check_vagrant_config(self) -> Self:
        # 1. check if box exists
        return self


class GCPConfig(Config):
    image: str

    @model_validator(mode="after")
    def check_vagrant_config(self) -> Self:
        return self


class AWSProvider(Config):
    provider: Literal["aws"]
    aws: AWSConfig

    def __eq__(self, value):
        if isinstance(value, AWSProvider):
            return self.aws.image == value.aws.image
        return super().__eq__(value)


class GCPProvider(Config):
    provider: Literal["gcp"]
    gcp: GCPConfig

    def __eq__(self, value):
        if isinstance(value, GCPProvider):
            return self.gcp.image == value.gcp.image
        return super().__eq__(value)


class VagrantProvider(Config):
    provider: Literal["vagrant"]
    vagrant: VagrantConfig

    def __eq__(self, value):
        if isinstance(value, VagrantProvider):
            return self.vagrant.box == value.vagrant.box
        return super().__eq__(value)


class SaveMode(Config):
    mode: Literal["save"]
    hosts: List[str]


class SpawnMode(Config):
    mode: Literal["spawn"]
    spawn: Union[VagrantProvider, AWSProvider, GCPProvider]
    count: int

    @model_validator(mode="after")
    def check_cfengine_config(self) -> Self:
        if self.count < 0:
            raise CFRConfigValidationError("'count' cannot be less than 0")
        return self

    def __eq__(self, value):
        if isinstance(value, SpawnMode):
            return self.spawn == value.spawn
        return super().__eq__(value)


class CFEngineConfig(Config):
    version: str
    bootstrap: str

    @model_validator(mode="after")
    def check_cfengine_config(self) -> Self:
        # 1. check that the cfengine version exists
        # 2. check that bootstrapping to an existing group, and it is a hub
        return self

    def __eq__(self, value):
        if isinstance(value, CFEngineConfig):
            return self.version == value.version and self.bootstrap == value.bootstrap
        return super().__eq__(value)


class GroupConfig(Config):
    role: Literal["client", "hub"]
    source: Union[SaveMode, SpawnMode]
    cfengine: Optional[CFEngineConfig] = None
    scripts: Optional[List[str]] = None

    @model_validator(mode="after")
    def check_group_config(self) -> Self:
        if self.scripts is None:
            return self

        for script in self.scripts:
            # race condition?
            if not os.path.exists(script):
                raise CFRConfigValidationError(
                    "Script '{}' doesn't exist".format(script)
                )

        if (
            self.role == "hub"
            and self.source.mode == "spawn"
            and self.source.count != 1
        ):
            raise CFRConfigValidationError("Hub groups cannot have more than one host")

        return self


def rgetattr(obj, attr, *args):
    def _getattr(obj, attr):
        return getattr(obj, attr, *args)

    return reduce(_getattr, [obj] + attr.split("."))


####################################


class Group:
    """
    All group-specific data:
    - Vagrantfile
    Config that declares it:
    - provider, count, cfengine version, role, ...
    """

    def __init__(self, config: GroupConfig):
        self.config = config
        self.hosts = []


class Host:
    """
    All host-specific data:
    - user, ip, ssh config, OS, uuid, ...
    """

    def __init__(self, id):
        self.id = id


def resolve_templates(parent, templates):
    if not parent:
        return
    if isinstance(parent, dict):
        for key, value in parent.items():
            if isinstance(value, str) and value in templates:
                parent[key] = templates[value]
            else:
                resolve_templates(value, templates)
    if isinstance(parent, list):
        for value in parent:
            resolve_templates(value, templates)


def validate_config(content):

    if not content:
        raise CFRConfigValidationError("Spawn config is empty")

    if not "groups" in content:
        raise CFRConfigValidationError("Missing 'groups' key in config")

    # 1. resolve template inside groups
    templates = content.get("templates")
    groups = content["groups"]
    if templates:
        resolve_templates(groups, templates)

    # 2. validate groups
    state = {}
    try:
        for g in groups:
            if len(g) != 1:
                raise CFRConfigValidationError(
                    "Too many keys in group definition: '{}'".format(list(g.keys()))
                )

            for k, v in g.items():
                state[k] = Group(GroupConfig(**v))

    except ValidationError as v:
        for err in v.errors():
            raise CFRConfigValidationError(
                "'{}' Validation Error: {}. Input '{}' at location '{}'".format(
                    err["type"], err["msg"], err["input"], err["loc"]
                )
            )

    return state


class Action(Enum):
    SPAWN = 0
    INSTALL = 1
    RUN = 2

from time import sleep

class Task:

    _id_counter = 0

    def __init__(
        self,
        old: Config | None,
        new: Config | None,
        action_type: Action,
        group_key: str,
    ):
        self.id = Task._id_counter
        Task._id_counter += 1
        self.old = old
        self.new = new

        self.action_type = action_type

        self.group_key = group_key
        self.dependencies = {}
        self.host = None

        self.time=0

    def depends_on(self, relationship: str, value: Host | Self):
        self.dependencies[relationship] = value.id

    def run(self) -> Host:
        print("Start '{}'".format(self.id))
        sleep(self.time)
        if self.action_type == Action.SPAWN:
            if self.old:
                config_destroy()
            if self.new:
                assert(isinstance(self.new, SaveMode) or isinstance(self.new, SaveMode))
                config_spawn(self.new)
        elif self.action_type == Action.INSTALL:
            if self.old:
                config_uninstall()
            if self.new:
                assert(isinstance(self.new, CFEngineConfig))
                config_install(self.new)
        else:
            if self.old:
                pass
            if self.new:
                pass
        print("End '{}'".format(self.id))

        if not self.host:
            return Host("")
        return self.host

    def __repr__(self):
        o = "*" if self.old else "Ø"
        n = "*" if self.new else "Ø"
        s = "Task<{}, {}, {}, ({}, {})>".format(
            str(self.id), str(self.action_type), self.group_key, o, n
        )
        for k, v in self.dependencies.items():
            s += " ({}: {})".format(k, str(v))
        return s


def generate_tasks(old_state, new_state):

    tasks = []
    new_keys_index = defaultdict(list)

    common_keys = new_state.keys() | old_state.keys()
    for key in common_keys:
        new_config = new_state.get(key)
        old_config = old_state.get(key)
        hosts = getattr(old_config, "hosts", [])

        spawn = None
        install = None
        new_source = rgetattr(new_config, "config.source", None)
        old_source = rgetattr(old_config, "config.source", None)
        new_cfengine = rgetattr(new_config, "config.cfengine", None)
        old_cfengine = rgetattr(old_config, "config.cfengine", None)
        new_scripts = rgetattr(new_config, "config.scripts", None)
        old_scripts = rgetattr(old_config, "config.scripts", None)

        # Update existing hosts
        for host in hosts:
            if old_source != new_source:
                spawn = Task(old_source, new_source, Action.SPAWN, key)
                spawn.depends_on("host", host)
                tasks.append(spawn)
                new_keys_index[key].append(spawn)

            if old_cfengine != new_cfengine and new_cfengine:
                dependency = spawn if spawn else host
                install = Task(old_cfengine, new_cfengine, Action.INSTALL, key)
                if dependency:
                    install.depends_on("host", dependency)
                tasks.append(install)

            if old_scripts != new_scripts and new_scripts:
                dependency = install if install else spawn if spawn else host
                scripts = Task(old_scripts, new_scripts, Action.RUN, key)
                if dependency:
                    scripts.depends_on("host", dependency)
                tasks.append(scripts)

        count = rgetattr(new_config, "config.source.count", 1)
        extra = count - len(hosts)

        # Create new hosts
        if extra > 0:
            for _ in range(extra):

                spawn = Task(None, new_source, Action.SPAWN, key)
                tasks.append(spawn)
                new_keys_index[key].append(spawn)

                if new_cfengine:
                    install = Task(None, new_cfengine, Action.INSTALL, key)
                    if spawn:
                        install.depends_on("host", spawn)
                    tasks.append(install)

                if new_scripts:
                    dependency = install if install else spawn
                    scripts = Task(None, new_scripts, Action.RUN, key)
                    if dependency:
                        scripts.depends_on("host", dependency)
                    tasks.append(scripts)

        # Make cfengine install depend on host existence for bootstrap
        for task in tasks:
            if not task.action_type == Action.INSTALL or not task.new:
                continue

            bootstrap = task.new.bootstrap
            if not bootstrap:
                continue

            parent = new_keys_index.get(bootstrap)
            if not parent:
                continue

            if len(parent) > 1:
                raise Exception("Cannot bootstrap to group with several hosts")
            elif len(parent) < 1:
                raise Exception("Cannot bootstrap to empty group")
            else:
                task.depends_on("bootstrap", parent[0])

    return tasks

import matplotlib.pyplot as plt
import networkx as nx

def schedule_tasks(current_state, tasks):

    # #############################

    # tasks = [Task(None, None, Action.SPAWN, ""),
    #         Task(None, None, Action.INSTALL, ""),
    #         Task(None, None, Action.RUN, ""),
    #         Task(None, None, Action.SPAWN, ""),
    #         Task(None, None, Action.INSTALL, ""),
    #         Task(None, None, Action.RUN, "")]
    
    # tasks[0].id = 0
    # tasks[1].id = 1
    # tasks[2].id = 2
    # tasks[3].id = 3
    # tasks[4].id = 4
    # tasks[5].id = 5
    
    # tasks[1].depends_on("host", tasks[0])
    # tasks[2].depends_on("host", tasks[1])
    # tasks[4].depends_on("host", tasks[3])
    # tasks[4].depends_on("bootstrap", tasks[0])
    # tasks[5].depends_on("host", tasks[1])

    # tasks[0].time = 1
    # tasks[1].time = 1
    # tasks[2].time = 1
    # tasks[3].time = 6
    # tasks[4].time = 1
    # tasks[5].time = 1

    # print([t.id for t in tasks])

    # #############################
    # edges = []
    # for t in tasks:
    #     for k, v in t.dependencies.items():
    #         edges.append((v, t.id))

    # G = nx.MultiDiGraph()
    # G.add_edges_from(edges)
    # plt.figure(figsize=(8,8))
    # nx.draw(G, connectionstyle='arc3, rad = 0.1', with_labels=True)
    # plt.savefig("a.png")
    # #############################

    id_to_degree = {}
    dependencies = defaultdict(list)
    for t in tasks:
        id_to_degree[t.id] = 0
        for v in t.dependencies.values():
            id_to_degree[t.id] +=1
            dependencies[v].append(t.id) # TODO: change direction of Task.dependencies, to not have to build this

    with concurrent.futures.ProcessPoolExecutor() as executor:
        futures = {}

        for t in tasks:
            if id_to_degree[t.id] == 0:
                f = executor.submit(t.run)
                futures[f] = t

        processed_count = 0
        while futures:
            done, _ = concurrent.futures.wait(
                futures, return_when=concurrent.futures.FIRST_COMPLETED
            )

            for f in done:
                finished_task = futures.pop(f)

                finished_task.result = f.result() # what if this fails? TODO: Try catch

                processed_count += 1
                for neighbour in dependencies[finished_task.id]:
                    id_to_degree[neighbour] -= 1
                    if id_to_degree[neighbour] == 0:
                        new_task = tasks[neighbour]

                        # Get host object to use/bootstrap to from result of parent run()
                        new_task.host = new_task.dependencies["host"].result
                        new_task.bootstrap = new_task.dependencies["bootstrap"].result

                        new_f = executor.submit(new_task.run)
                        futures[new_f] = new_task

# import commands

def config_spawn(config: SpawnMode | SaveMode):
    
    if config.mode == "spawn":
        pass
    else:
        pass

def config_destroy():
    pass

def config_install(config: CFEngineConfig):
    pass


def config_uninstall():
    pass
