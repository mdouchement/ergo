package forwarder

import (
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/mdouchement/ergo/tcp"
	"github.com/mdouchement/logger"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Command is used to forward incoming TCP connections over TLS.
func Command() *cobra.Command {
	var listen string

	c := &cobra.Command{
		Use:   "tls-forwarder",
		Short: "Forwards TCP connections to the Ergo server through TLS",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
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

			addr := args[0]
			cfg := &tls.Config{
				ServerName: trimport(addr),
			}

			//

			if err := check(log, addr, cfg); err != nil {
				return err
			}

			//

			log.Info("Listening on ", listen)
			l, err := net.Listen("tcp", listen)
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

					//
					// TCP connection
					//

					rc, err := net.Dial("tcp", addr)
					if err != nil {
						log.WithError(err).Error("could not connect to Ergo proxy")
						return
					}
					defer rc.Close()
					rc.(*net.TCPConn).SetKeepAlive(true)

					//
					// TLS handshake
					//

					sc := tls.Client(rc, cfg)
					if err = sc.Handshake(); err != nil {
						log.WithError(err).Error("could not perform TLS on Ergo proxy")
						return
					}
					defer sc.Close()

					//
					// TCP pipeline
					//

					pipe, err := tcp.NewPipe(c, sc)
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
					}).Info(tlsinfo(sc.ConnectionState()))

					err = pipe.Relay()
					if err != nil && !tcp.IsIgnorableError(err) {
						log.WithError(err).Error("pipe failure")
					}
				}()
			}
		},
	}
	c.Flags().StringVarP(&listen, "binding", "b", "localhost:8080", "Forwarder listening address")

	return c
}

func check(l logger.Logger, addr string, cfg *tls.Config) error {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return errors.Wrap(err, "could not connect to Ergo proxy")
	}
	defer c.Close()

	sc := tls.Client(c, cfg)
	if err = sc.Handshake(); err != nil {
		return errors.Wrap(err, "could not perform TLS on Ergo proxy")
	}
	defer sc.Close()

	cs := sc.ConnectionState()
	l.Info("TLS details:")
	l.Info("ServerName:     ", cs.ServerName)
	l.Info("Version:        ", version(cs.Version))
	l.Info("CipherSuite:    ", tls.CipherSuiteName(cs.CipherSuite))
	l.Info("")
	l.Info("Address:        ", sc.RemoteAddr().String())
	l.Info("CommonName:     ", cs.PeerCertificates[0].Subject.CommonName)
	l.Info("Issuer:         ", cs.PeerCertificates[0].Issuer.CommonName)
	l.Info("NotBefore:      ", cs.PeerCertificates[0].NotBefore.In(time.Local).String())
	l.Info("NotAfter:       ", cs.PeerCertificates[0].NotAfter.In(time.Local).String())
	l.Info("")
	return nil
}

func trimport(addr string) string {
	idx := strings.Index(addr, ":")
	if idx < 1 {
		return addr
	}
	return addr[:idx]

}

func tlsinfo(cs tls.ConnectionState) string {
	return fmt.Sprintf("Forwarding to %s with %s (%s)",
		cs.ServerName,
		version(cs.Version),
		tls.CipherSuiteName(cs.CipherSuite),
	)
}

func version(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("%d", v)
	}
}
