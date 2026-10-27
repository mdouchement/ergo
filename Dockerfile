# build stage
FROM golang:alpine AS build-env
LABEL maintainer="mdouchement"

RUN apk upgrade

ENV CGO_ENABLED=0
ENV GO111MODULE=on

WORKDIR /ergo
COPY . .

RUN go mod download
RUN go build -ldflags "-s -w" -o ergo .

# Prepare Scratch for runtime and security purposes.
RUN echo "nobody:x:65534:65534:nobody:/_nonexistent:/bin/false" > /etc_passwd

# final stage
FROM scratch
LABEL maintainer="mdouchement"

COPY --from=build-env /ergo/ergo /usr/local/bin/

# Setup Scratch image to be secure.
COPY --from=build-env /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build-env /etc_passwd /etc/passwd
USER nobody

# export ERGO_PROXY_CONFIG in your docker-compose.yml
EXPOSE 8080
CMD ["/usr/local/bin/ergo", "server"]
