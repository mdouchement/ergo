package server

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"regexp"

	"github.com/ghodss/yaml"
	"github.com/mdouchement/ergo/host"
	"github.com/mdouchement/ergo/http"
	"github.com/mdouchement/ergo/tcp"
	"github.com/mdouchement/logger"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type configuration struct {
	*host.PatternMatcher
	Address       string   `json:"addr"`
	Authorization string   `json:"authorization"`
	Logger        string   `json:"logger"`
	DenyList      []string `json:"denylist"`
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

			logr := logrus.New()
			logr.SetFormatter(&logger.LogrusTextFormatter{
				DisableColors:   false,
				ForceColors:     true,
				ForceFormatting: true,
				PrefixRE:        regexp.MustCompile(`^(\[.*?\])\s`),
				FullTimestamp:   true,
				TimestampFormat: "2006-01-02 15:04:05",
			})
			log := logger.WrapLogrus(logr)

			//

			var config configuration
			{

				log.Infof("Reading configuration from %s", cfg)
				payload, err := ioutil.ReadFile(cfg)
				if err != nil {
					if err != nil {
						return errors.Wrapf(err, "could not read configuration file %s", cfg)
					}
				}

				err = yaml.Unmarshal(payload, &config)
				if err != nil {
					if err != nil {
						return errors.Wrapf(err, "could not parse configuration file %s", cfg)
					}
				}

				if config.Logger != "" {
					l, err := logrus.ParseLevel(config.Logger)
					if err != nil {
						return errors.Wrapf(err, "could not parse logger level %s", cfg)
					}
					logr.SetLevel(l)
				}

				config.PatternMatcher = host.NewPatternMatcher(log)
				for line, pattern := range config.DenyList {
					err = config.PatternMatcher.Add(pattern, struct{}{}, line+1)
					if err != nil {
						return errors.Wrapf(err, "could not build denylist %s", cfg)
					}
				}
			}

			//
			//
			//

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

					{
						lookups := []string{header.Domain()}
						if ips, err := net.LookupHost(lookups[0]); err == nil {
							lookups = append(lookups, ips...)
						}

						for _, lookup := range lookups {
							if rejected, reason, _ := config.PatternMatcher.Eval(lookup); rejected {
								const payload = "HTTP/1.1 403 Forbidden\r\n\r\n"
								log.Info(header.String())
								log.Warnf("rejected by rule: %s", reason)
								c.Write([]byte(payload))
								return
							}
						}

					}

					//
					// TCP pipeline
					//

					pipe, err := tcp.NewPipeTCP(c, header.Host())
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
