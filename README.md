# Ergo

Ergo is an HTTP/HTTPS proxy that supports `Proxy-Authorization` authentication.
Ergo is able to deny destinations according its configuration.

## How does it work

### HTTP

1. Accept TCP connection
2. Catch the request header
3. Open the TCP tunnel to the remote
4. Forward through TCP pipeline the whole request to the remote

### HTTPS

1. Accept TCP connection
2. Catch CONNECT request
3. Open the TCP tunnel to the remote provided by the CONNECT request. So it supports HTTP2 multiplexed flow
4. Respond `200 OK` to the client to inform the tunnel is opened
5. Forward through TCP pipeline all the raw data

## tls-forwarder

Useful when Ergo is behind a router like Traefik with TLS enabled and your client doesn't support TLS proxy endpoint.

Workflow:
1. Forwarder opens a TCP connection to Ergo through the router
2. Perform TLS handshake with the router TLS
3. Forward through TCP pipeline all the raw data to be proxified

## License

**MIT**


## Contributing

All PRs are welcome.

1. Fork it
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
5. Push to the branch (git push origin my-new-feature)
6. Create new Pull Request