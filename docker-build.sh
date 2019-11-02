#!/bin/sh
set -e

docker build -f Dockerfile -t github-oauth-proxy:latest --no-cache=true --force-rm=true ./
