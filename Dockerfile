# build stage
FROM golang:alpine as build-env
LABEL maintainer="mdouchement"

RUN apk upgrade

ENV CGO_ENABLED 0
ENV GO111MODULE on

WORKDIR /ergo
COPY . .

RUN go mod download
RUN go build -ldflags "-s -w" -o ergo .

# final stage
FROM scratch
LABEL maintainer="mdouchement"

COPY --from=build-env /ergo/ergo /usr/local/bin/

# export ERGO_PROXY_CONFIG in your docker-compose.yml
EXPOSE 8080
CMD ["/usr/local/bin/ergo", "server"]
