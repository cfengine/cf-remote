import setuptools
import subprocess

cf_remote_version = subprocess.run(['git', 'describe', '--tags'], stdout=subprocess.PIPE).stdout.decode("utf-8").strip()
assert "." in cf_remote_version

with open("cf_remote/version.py", "r", encoding="utf-8") as fh:
    version_module = fh.read()

assert "UNKOWN_VERSION" in version_module

version_module = version_module.replace("UNKOWN_VERSION", cf_remote_version)

with open("cf_remote/version.py", "w", encoding="utf-8") as fh:
    fh.write(version_module)

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="cf-remote",
    version=cf_remote_version,
    author="Northern.tech, Inc.",
    author_email="contact@northern.tech",
    description="Tooling to deploy CFEngine (and much more)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/cfengine/cf-remote",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    entry_points={
        "console_scripts": [
            "cf-remote = cf_remote.main:main"
        ]
    },
    install_requires=[
      "cryptography >= 3.3.1",
      "fabric >= 2.6.0",
      "paramiko >= 2.7.2",
      "requests >= 2.25.1",
      "apache-libcloud >= 3.3.0"
    ],
)
