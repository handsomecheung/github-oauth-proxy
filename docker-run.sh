#!/bin/bash
set -e

image=github-oauth-proxy:latest
service=github-oauth-proxy

docker stop ${service} || true
docker rm -f ${service} || true
docker run -d \
      --restart always \
      --name ${service} \
      --hostname ${service} \
      --net bridge \
      --publish 32865:8000/tcp \
      --env "TZ=Asia/Shanghai" \
      ${image}
