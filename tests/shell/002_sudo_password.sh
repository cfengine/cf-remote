#!/usr/bin/env bash
# Check that cf-remote can switch user on hosts where sudo asks for a password,
# which is the normal case in environments that don't hand out NOPASSWD sudo.
set -ex
set -o pipefail

if ! docker info >/dev/null 2>&1; then
  echo "--- SKIP: docker is not available"
  exit 0
fi

# The build context lives with the other docker fixtures
dir=$(dirname "$0")/../docker/sudo
name=cf-remote-sudo-password-test-host
port=8823
password=cftestpw
pwfile=$(mktemp)

# Leave nothing behind, including on Ctrl+C: a container holding the port, a
# throwaway SSH key, a password file and an ssh-agent
cleanup () {
  ssh-agent -k >/dev/null 2>&1 || true
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -f "$dir/id_test" "$dir/id_test.pub" "$pwfile"
}
trap cleanup EXIT INT TERM

out=""
# Run cf-remote with a password on stdin, keeping the output in $out. Some of
# the cases below are expected to fail, so the exit code is not what we assert
# on, the output is.
run_cfr () {
  local pw="$1"; shift
  set +e
  out=$(printf '%s\n' "$pw" | "$@" 2>&1)
  set -e
  printf '%s\n' "$out"
}

assert_output () {  # assert_output <grep args...>
  if printf '%s\n' "$out" | grep -q "$@"; then
    echo "ok: output matched '$*'"
  else
    echo "FAIL: output did not match '$*'"
    exit 1
  fi
}

# SSH logs in with a key, so the account password is only used by sudo
rm -f "$dir/id_test" "$dir/id_test.pub"
ssh-keygen -t ed25519 -N "" -f "$dir/id_test" -q
docker build -t "$name" "$dir"
docker run -d -p "$port":22 --name "$name" "$name"

# scp doesn't take the key from CF_REMOTE_SSH_KEY, so use an agent
eval "$(ssh-agent -s)"
ssh-add "$dir/id_test"

# The port is published, so the host is reachable on the loopback address.
# 'hostname -i' can answer with several addresses, which would not be.
host=127.0.0.1
ready=no
for _ in $(seq 30); do
  if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -p "$port" cftest@"$host" true; then
    ready=yes
    break
  fi
  sleep 1
done
if [ "$ready" != yes ]; then
  echo "FAIL: '$name' never accepted an SSH connection on port $port"
  exit 1
fi

echo "=== without --ask-pass: should say what is wrong ==="
run_cfr "" cf-remote sudo -H cftest@"$host":"$port" 'id -un'
assert_output -- "--ask-pass"

echo "=== with --ask-pass: should run as root ==="
run_cfr "$password" cf-remote --ask-pass sudo -H cftest@"$host":"$port" 'id -un'
assert_output "root"

echo "=== with a wrong password: should say it was rejected ==="
run_cfr "definitely-not-the-password" \
  cf-remote --ask-pass sudo -H cftest@"$host":"$port" 'id -un'
assert_output -i "rejected"

echo "=== NOPASSWD host: the password must not reach the command ==="
run_cfr "$password" cf-remote --ask-pass sudo -H cfnopass@"$host":"$port" 'cat'
if printf '%s\n' "$out" | grep -q "$password"; then
  echo "FAIL: password ended up on the standard input of the command"
  exit 1
fi
echo "ok: no password sent where none was needed"

echo "=== --switch-user-command is used as given ==="
run_cfr "$password" cf-remote --ask-pass \
  --switch-user-command "sudo -S -p '' /bin/sh -c" \
  sudo -H cftest@"$host":"$port" 'readlink /proc/$$/exe'
assert_output "sh"

echo "=== a command carrying a quote of its own survives ==="
quoted_payload='echo "it'"'"'s fine"'
run_cfr "$password" cf-remote --ask-pass sudo -H cftest@"$host":"$port" "$quoted_payload"
assert_output "it's fine"

echo "=== --password-file needs nobody to answer a prompt ==="
chmod 600 "$pwfile"
printf '%s\n' "$password" > "$pwfile"
run_cfr "" cf-remote --password-file "$pwfile" sudo -H cftest@"$host":"$port" 'id -un'
assert_output "root"

echo "=== a password file others can read is refused ==="
chmod 644 "$pwfile"
run_cfr "" cf-remote --password-file "$pwfile" sudo -H cftest@"$host":"$port" 'id -un'
assert_output "readable by others"

echo "=== install with a sudo password ==="
chmod 600 "$pwfile"
run_cfr "$password" cf-remote --ask-pass install --edition community \
  --clients cftest@"$host":"$port"
assert_output "successfully installed"

echo "=== all sudo password tests passed ==="
