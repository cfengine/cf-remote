#!/usr/bin/env bash
set -ex
error () {
  echo "=== an error occurred, logs follow ==="
  cat log
}
trap error ERR

dir=$(dirname "$0")
name=cf-remote-debian-test-host

docker stop "$name" || true
docker rm "$name" || true
docker build -t "$name" "$dir" >log 2>&1
docker run -d -p 8822:22 --name "$name" "$name" >>log 2>&1
ip_addr=$(hostname -i)
ssh -o StrictHostKeyChecking=no -p 8822 root@"$ip_addr" hostname >>log 2>&1
echo "ssh returned exit code $?"
false
cf-remote --log-level DEBUG install --clients root@"$ip_addr":8822 2>&1 | tee -a log
ssh -o StrictHostKeyChecking=no -p 8822 root@"$ip_addr" cf-agent -V >>log 2>&1
