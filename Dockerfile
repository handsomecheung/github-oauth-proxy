FROM golang as builder

COPY build.sh /tmp
COPY main.go /tmp
RUN cd /tmp && chmod +x build.sh && ./build.sh


FROM alpine:3.9
LABEL MAINTAINER="hc <handsomecheung@gmail.com>"

RUN apk add --update tzdata ca-certificates

COPY --from=builder /tmp/github-oauth-proxy /root/github-oauth-proxy/
COPY passphrase /root/github-oauth-proxy/

ENTRYPOINT ["/root/github-oauth-proxy/github-oauth-proxy"]