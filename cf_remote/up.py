from pydantic import BaseModel, model_validator, ValidationError, Field
from typing import Union, Literal, Optional, List, Annotated
from functools import reduce

from cf_remote.utils import CFRUserError
from cf_remote import log

import cf_remote.validate as validate


# Forces pydantic to throw validation error if config contains unknown keys
class NoExtra(BaseModel, extra="forbid"):
    pass


class Config(NoExtra):
    pass


class AWSConfig(Config):
    image: str
    size: Literal["micro", "xlarge"] = "micro"

    @model_validator(mode="after")
    def check_aws_config(self):
        validate.validate_aws_image(self.image)
        return self


class VagrantConfig(Config):
    box: str
    memory: int = 512
    cpus: int = 1
    sync_folder: Optional[str] = None
    provision: Optional[str] = None

    @model_validator(mode="after")
    def check_vagrant_config(self):
        if self.memory < 512:
            raise CFRUserError("Cannot allocate less than 512MB to a Vagrant VM")
        if self.cpus < 1:
            raise CFRUserError("Cannot use less than 1 cpu per Vagrant VM")

        validate.validate_vagrant_box(self.box)

        return self


class GCPConfig(Config):
    image: str  # There is no list of avalaible GCP platforms to validate against yet
    network: Optional[str] = None
    public_ip: bool = True
    size: str = "n1-standard-1"


class AWSProvider(Config):
    provider: Literal["aws"]
    aws: AWSConfig

    @model_validator(mode="after")
    def check_aws_provider(self):
        validate.validate_aws_credentials()
        return self


class GCPProvider(Config):
    provider: Literal["gcp"]
    gcp: GCPConfig

    @model_validator(mode="after")
    def check_gcp_provider(self):
        validate.validate_gcp_credentials()
        return self


class VagrantProvider(Config):
    provider: Literal["vagrant"]
    vagrant: VagrantConfig


class SaveMode(Config):
    mode: Literal["save"]
    hosts: List[str]


class SpawnMode(Config):
    mode: Literal["spawn"]
    # "Field" forces pydantic to report errors on the branch defined by the field "provider"
    spawn: Annotated[
        Union[VagrantProvider, AWSProvider, GCPProvider],
        Field(discriminator="provider"),
    ]
    count: int

    @model_validator(mode="after")
    def check_spawn_config(self):
        if self.count < 1:
            raise CFRUserError("Cannot spawn less than 1 instance")
        return self


class CFEngineConfig(Config):
    version: Optional[str] = None
    bootstrap: Optional[str] = None
    edition: Literal["community", "enterprise"] = "enterprise"
    remote_download: bool = False
    hub_package: Optional[str] = None
    client_package: Optional[str] = None
    package: Optional[str] = None
    demo: bool = False

    @model_validator(mode="after")
    def check_cfengine_config(self):
        packages = [self.package, self.hub_package, self.client_package]
        for p in packages:
            validate.validate_package(p, self.remote_download)

        if self.version and any(packages):
            log.warning("Specifying package overrides cfengine version")

        validate.validate_version(self.version, self.edition)
        validate.validate_state_bootstrap(self.bootstrap)

        return self


class GroupConfig(Config):
    role: Literal["client", "hub"]
    # "Field" forces pydantic to report errors on the branch defined by the field "provider"
    source: Annotated[Union[SaveMode, SpawnMode], Field(discriminator="mode")]
    cfengine: Optional[CFEngineConfig] = None
    scripts: Optional[List[str]] = None

    @model_validator(mode="after")
    def check_group_config(self):
        if (
            self.role == "hub"
            and self.source.mode == "spawn"
            and self.source.count != 1
        ):
            raise CFRUserError("A hub can only have one host")

        return self


def rgetattr(obj, attr, *args):
    def _getattr(obj, attr):
        return getattr(obj, attr, *args)

    return reduce(_getattr, [obj] + attr.split("."))


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

    def __init__(self):
        pass


def _resolve_templates(parent, templates):
    if not parent:
        return
    if isinstance(parent, dict):
        for key, value in parent.items():
            if isinstance(value, str) and value in templates:
                parent[key] = templates[value]
            else:
                _resolve_templates(value, templates)
    if isinstance(parent, list):
        for value in parent:
            _resolve_templates(value, templates)


def validate_config(content):
    if not content:
        raise CFRUserError("Empty spawn config")

    if "groups" not in content:
        raise CFRUserError("Missing 'groups' key in spawn config")

    groups = content["groups"]
    templates = content.get("templates")
    if templates:
        _resolve_templates(groups, templates)

    if not isinstance(groups, list):
        groups = [groups]

    state = {}
    try:
        for g in groups:
            if len(g) != 1:
                raise CFRUserError(
                    "Too many keys in group definition: {}".format(
                        ", ".join(list(g.keys()))
                    )
                )

            for k, v in g.items():
                state[k] = Group(GroupConfig(**v))

    except ValidationError as v:
        msgs = []
        for err in v.errors():
            msgs.append(
                "{}. Input '{}' at location '{}'".format(
                    err["msg"], err["input"], err["loc"]
                )
            )
        raise CFRUserError("\n".join(msgs))
