#!/bin/bash
set -e

dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd $dir

bash build.sh
docker build -f Dockerfile -t github-oauth-proxy:latest --no-cache=true --force-rm=true ./
