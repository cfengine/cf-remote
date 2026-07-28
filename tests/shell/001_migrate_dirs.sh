set -e
set -x

mkdir -p ~/.cfengine/cf-remote/json/
mkdir -p ~/.cfengine/cf-remote/packages/
touch ~/.cfengine/cf-remote/json/test_file.json
touch ~/.cfengine/cf-remote/packages/test_pkg.tar.gz
touch ~/.cfengine/cf-remote/test_config

cf-remote -V

! test -e ~/.cfengine/cf-remote

test -f ~/.config/cfengine/cf-remote/test_config
! test -e ~/.config/cfengine/cf-remote/json

test -f ~/.cache/cfengine/cf-remote/json/test_file.json
test -f ~/.cache/cfengine/cf-remote/packages/test_pkg.tar.gz
