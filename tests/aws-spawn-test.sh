#!/usr/bin/env bash
set -ex

function cleanup() {
  cf-remote destroy --all
}

trap cleanup ERR
trap cleanup EXIT

# this is a fairly exhaustive test and will take some time
# spawn all reasonable "platform" specifications
function test_spawn() {
  platform=$1
  version=$2

  for role in client hub; do
    cf-remote spawn --count 1 --platform "$platform-$version" --role "$role" --name "$platform-$version-$role"
    cleanup
  done
}

function fail() {
  echo "FAIL: $@"
  exit 1
}

# start with cleanup
cleanup

# test some negative cases
set +e
cf-remote spawn --count 1 --platform ubuntu --role client --name test && fail "ubuntu platform requires a version"
cleanup

set -e

# test some basic day to day cases
# for testing, include ubuntu and centos which require versions
for platform in debian-12-x64 debian-12-arm64; do
  cf-remote spawn --count 1 --platform $platform --role client --name $platform
  cleanup
done
for platform in debian rhel windows debian-9 ubuntu-22 centos-7 rhel-9 windows-2019; do
  cf-remote spawn --count 1 --platform $platform --role client --name $platform
  cleanup
done
for version in 9 10 11 12; do
  test_spawn debian $version
done
for version in 7 8; do
  test_spawn centos $version
done
for version in 7 8 9; do
  test_spawn rhel $version
done
for version in 2008 2012 2016 2019 2022; do
  test_spawn windows $version
done
for version in 16-04 18-04 20-04 22-04; do
  test_spawn ubuntu "$version"
done
test_spawn alpine
