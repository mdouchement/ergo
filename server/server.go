package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"regexp"

	"github.com/mdouchement/ergo/http"
	"github.com/mdouchement/ergo/resolver"
	"github.com/mdouchement/ergo/tcp"
	"github.com/mdouchement/logger"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

type configuration struct {
	*resolver.NameResolver
	Address       string   `yaml:"addr"`
	Authorization string   `yaml:"authorization"`
	NameServer    string   `yaml:"force_nameserver"`
	Logger        string   `yaml:"logger"`
	DenyList      []string `yaml:"denylist"`
}

// Command is used to launch Ergo proxy server.
func Command() *cobra.Command {
	var cfg string

	c := &cobra.Command{
		Use:   "server",
		Short: "Starts the Ergo proxy server",
		Args:  cobra.ExactArgs(0),
		RunE: func(_ *cobra.Command, _ []string) error {
			if cfg == "" {
				cfg = "ergo.yml"
			}

			lopts := &logger.SlogTextOption{
				DisableColors:   false,
				ForceColors:     true,
				ForceFormatting: true,
				PrefixRE:        regexp.MustCompile(`^(\[.*?\])\s`),
				FullTimestamp:   true,
				TimestampFormat: "2006-01-02 15:04:05",
			}
			log := logger.WrapSlogHandler(logger.NewSlogTextHandler(os.Stdout, lopts))

			//

			var config configuration
			{

				log.Infof("Reading configuration from %s", cfg)
				payload, err := os.ReadFile(cfg)
				if err != nil {
					return errors.Wrapf(err, "could not read configuration file %s", cfg)
				}

				err = yaml.Unmarshal(payload, &config)
				if err != nil {
					return errors.Wrapf(err, "could not parse configuration file %s", cfg)
				}

				if config.Logger != "" {
					lopts.Level, err = logger.ParseSlogLevel(config.Logger)
					if err != nil {
						return errors.Wrapf(err, "could not parse logger level %s", cfg)
					}

					log = logger.WrapSlogHandler(logger.NewSlogTextHandler(os.Stdout, lopts))
				}

				config.NameResolver, err = resolver.New(config.NameServer, config.DenyList)
				if err != nil {
					return errors.Wrapf(err, "could not build name resolver %s", cfg)
				}
			}

			//
			//
			//

			if config.Authorization != "" {
				log.Info("Authorization enabled")
			} else {
				log.Info("Authorization disabled")
			}

			if config.NameServer != "" {
				log.Info("Name server forced to", config.NameServer)
			}

			log.Info("Listening on ", config.Address)
			l, err := net.Listen("tcp", config.Address)
			if err != nil {
				return errors.Wrap(err, "could not listen")
			}

			for {
				c, err := l.Accept()
				if err != nil {
					if !tcp.IsIgnorableError(err) {
						log.WithError(err).Error("could not accept")
					}
					continue
				}

				go func() {
					defer c.Close()
					c.(*net.TCPConn).SetKeepAlive(true)

					c, header, err := http.Proxy(c)
					if err != nil {
						log.Error(err)
						return
					}

					//
					// Authorization
					//

					if config.Authorization != "" {
						const payload = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Access to internal site\"\r\n\r\n"

						user, password, ok := header.ProxyBasicAuth()
						if !ok {
							log.Info(header.String())
							log.Error("no autorization provided")
							c.Write([]byte(payload))
							return
						}
						if fmt.Sprintf("%s:%s", user, password) != config.Authorization {
							log.Info(header.String())
							log.Error("invalid autorization provided")
							c.Write([]byte(payload))
							return
						}
					}

					//
					// Deny check
					//

					var ip net.IP
					{
						_, ip, err = config.Resolve(context.Background(), header.Domain())
						if err != nil {
							const payload = "HTTP/1.1 403 Forbidden\r\n\r\n"
							log.Info(header.String())
							log.Warn(err)
							c.Write([]byte(payload))
							return
						}
					}

					//
					// TCP pipeline
					//

					pipe, err := tcp.NewPipeTCP(c, net.JoinHostPort(ip.String(), header.Port()))
					if err != nil {
						if !tcp.IsIgnorableError(err) {
							log.WithError(err).Error("failed to establish pipe")
						}
						return
					}
					defer pipe.Close()

					log.WithFields(logger.M{
						"local":  fmt.Sprintf("%s/%s", pipe.LocalConn().LocalAddr(), pipe.LocalConn().RemoteAddr()),
						"remote": fmt.Sprintf("%s/%s", pipe.RemoteConn().LocalAddr(), pipe.RemoteConn().RemoteAddr()),
					}).Infof("%s %s", header.Method, header.Host())

					if header.Method == "CONNECT" {
						// Once connected successfully, return OK
						c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
					}

					err = pipe.Relay()
					if err != nil && !tcp.IsIgnorableError(err) {
						log.WithError(err).Error("pipe failure")
					}
				}()
			}
		},
	}
	c.Flags().StringVarP(&cfg, "config", "c", os.Getenv("ERGO_PROXY_CONFIG"), "Server's configuration")

	return c
}
