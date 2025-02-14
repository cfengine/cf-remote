aws_defaults = {
    "architecture": "x86_64",
    "sizes": {
        "x86_64": {
            "size": "t2.micro",
            "xlsize": "t2.xlarge",
        },
        "arm64": {
            "size": "t4g.micro",
            "xlsize": "t4g.xlarge",
        },
    },
    "user": "ec2-user",
}
aws_image_criteria = {
    "debian": {
        "owner_id": "136693071363",
        "name_pattern": "debian-{version}*",
        "user": "admin",
    },
    "alpine": {
        "owner_id": "538276064493",
        "name_pattern": "alpine-{version}-*",
        "user": "alpine",
        "sizes": {
            "x86_64": {
                "size": "t3.micro",
                "xlsize": "t3.xlarge",
            },
            "arm64": {
                "size": "t4g.micro",
                "xlsize": "t4g.xlarge",
            },
        },
    },
    "ubuntu-16": {
        "owner_id": "099720109477",
        "name_pattern": "ubuntu-pro-server/images/hvm-ssd/ubuntu-xenial-16.04-amd64-pro-server*",
        "user": "ubuntu",
    },
    "ubuntu-24": {
        "owner_id": "099720109477",
        "name_pattern": "ubuntu/images/hvm-ssd-gp3/ubuntu-*-{version}*",
        "user": "ubuntu",
    },
    "ubuntu": {
        "owner_id": "099720109477",
        "name_pattern": "ubuntu/images/hvm-ssd/ubuntu-*-{version}*",
        "user": "ubuntu",
    },
    "centos": {
        "note": "This owner is our nt-dev account in AWS so these are private custom images.",
        "owner_id": "304194462000",
        "name_pattern": "centos-{version}-x64",
        "region": "eu-west-1",
        "user": "centos",
    },
    "rhel": {
        "owner_id": "309956199498",
        "name_pattern": "RHEL-{version}*",
    },
    "windows-2008": {
        "ami": "ami-09046e654c804633f",
        "user": "Administrator",
        "region": "eu-west-1",
    },
    "windows-2012": {
        "ami": "ami-0444b0c023c7f3671",
        "user": "Administrator",
        "region": "eu-west-1",
    },
    "windows-2016": {
        "ami": "ami-00a7e5468b339302c",
        "user": "Administrator",
        "region": "eu-west-1",
    },
    "windows-2019": {
        "ami": "ami-0311c2819c6a29312",
        "user": "Administrator",
        "region": "eu-west-1",
    },
    "windows": {
        "note": "Note that typically we rely on custom pre-configured windows imimages with ssh installed and pre-populated public keys so an image spawned from this criteria will not come with ssh built-in and ready to go.",
        "owner_id": "801119661308",
        "name_pattern": "Windows_Server-{version}-English-Core-Base*",
        "user": "Administrator",
    },
    "suse": {"owner_id": "013907871322", "name_pattern": "suse-sles-{version}*"},
}
