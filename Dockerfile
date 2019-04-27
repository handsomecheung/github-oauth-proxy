FROM alpine:3.9
LABEL MAINTAINER="hc <handsomecheung@gmail.com>"

RUN apk add --update tzdata ca-certificates
ADD github-oauth-proxy /root/github-oauth-proxy/
ADD passphrase /root/github-oauth-proxy/

ENTRYPOINT ["/root/github-oauth-proxy/github-oauth-proxy"]