package forwarder

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/mdouchement/ergo/tcp"
	"github.com/mdouchement/logger"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/blake2b"
)

type controler struct {
	logger      logger.Logger
	tls         *tls.Config
	skip        bool
	listen      string
	address     string
	fingerprint string
}

// Command is used to forward incoming TCP connections over TLS.
func Command() *cobra.Command {
	ctrl := &controler{}

	c := &cobra.Command{
		Use:   "tls-forwarder",
		Short: "Forwards TCP connections to the Ergo server through TLS",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			log := logrus.New()
			log.SetFormatter(&logger.LogrusTextFormatter{
				DisableColors:   false,
				ForceColors:     true,
				ForceFormatting: true,
				PrefixRE:        regexp.MustCompile(`^(\[.*?\])\s`),
				FullTimestamp:   true,
				TimestampFormat: "2006-01-02 15:04:05",
			})
			ctrl.logger = logger.WrapLogrus(log)

			ctrl.address = args[0]
			ctrl.tls = &tls.Config{
				ServerName: trimport(ctrl.address),
			}

			//

			if err := ctrl.check(); err != nil {
				return err
			}

			//

			ctrl.logger.Info("Listening on ", ctrl.listen)
			l, err := net.Listen("tcp", ctrl.listen)
			if err != nil {
				return errors.Wrap(err, "could not listen")
			}

			for {
				c, err := l.Accept()
				if err != nil {
					if !tcp.IsIgnorableError(err) {
						ctrl.logger.WithError(err).Error("could not accept")
					}
					continue
				}

				go func() {
					defer c.Close()
					c.(*net.TCPConn).SetKeepAlive(true)

					//
					// TCP connection
					//

					rc, err := net.Dial("tcp", ctrl.address)
					if err != nil {
						log.WithError(err).Error("could not connect to Ergo proxy")
						return
					}
					defer rc.Close()
					rc.(*net.TCPConn).SetKeepAlive(true)

					//
					// TLS handshake
					//

					sc := tls.Client(rc, ctrl.tls)
					if err = sc.Handshake(); err != nil {
						ctrl.logger.WithError(err).Error("could not perform TLS on Ergo proxy")
						return
					}
					defer sc.Close()

					if !ctrl.valid(sc) {
						ctrl.logger.Fatal("The TLS fingerprint has changed")
					}

					//
					// TCP pipeline
					//

					pipe, err := tcp.NewPipe(c, sc)
					if err != nil {
						if !tcp.IsIgnorableError(err) {
							ctrl.logger.WithError(err).Error("failed to establish pipe")
						}
						return
					}
					defer pipe.Close()

					ctrl.logger.WithFields(logger.M{
						"local":  fmt.Sprintf("%s/%s", pipe.LocalConn().LocalAddr(), pipe.LocalConn().RemoteAddr()),
						"remote": fmt.Sprintf("%s/%s", pipe.RemoteConn().LocalAddr(), pipe.RemoteConn().RemoteAddr()),
					}).Info(tlsinfo(sc.ConnectionState()))

					err = pipe.Relay()
					if err != nil && !tcp.IsIgnorableError(err) {
						ctrl.logger.WithError(err).Error("pipe failure")
					}
				}()
			}
		},
	}
	c.Flags().StringVarP(&ctrl.listen, "binding", "b", "localhost:8080", "Forwarder listening address")
	c.Flags().BoolVarP(&ctrl.skip, "skip", "", false, "Skip human validation for certficate details")

	return c
}

func (ctrl *controler) check() error {
	c, err := net.Dial("tcp", ctrl.address)
	if err != nil {
		return errors.Wrap(err, "could not connect to Ergo proxy")
	}
	defer c.Close()

	sc := tls.Client(c, ctrl.tls)
	if err = sc.Handshake(); err != nil {
		return errors.Wrap(err, "could not perform TLS on Ergo proxy")
	}
	defer sc.Close()

	cs := sc.ConnectionState()
	ctrl.logger.Info("TLS details:")
	ctrl.logger.Info("ServerName:     ", cs.ServerName)
	ctrl.logger.Info("Version:        ", version(cs.Version))
	ctrl.logger.Info("CipherSuite:    ", tls.CipherSuiteName(cs.CipherSuite))
	ctrl.logger.Info("")
	ctrl.logger.Info("Address:        ", sc.RemoteAddr().String())
	ctrl.logger.Info("CommonName:     ", cs.PeerCertificates[0].Subject.CommonName)
	ctrl.logger.Info("Issuer:         ", cs.PeerCertificates[0].Issuer.CommonName)
	ctrl.logger.Info("NotBefore:      ", cs.PeerCertificates[0].NotBefore.In(time.Local).String())
	ctrl.logger.Info("NotAfter:       ", cs.PeerCertificates[0].NotAfter.In(time.Local).String())
	ctrl.logger.Info("")

	if !ctrl.skip {
		pause()
	}

	ctrl.fingerprint = fingerprint(cs.PeerCertificates[0])
	return nil
}

func (ctrl *controler) valid(sc *tls.Conn) bool {
	return ctrl.fingerprint == fingerprint(sc.ConnectionState().PeerCertificates[0])
}

func fingerprint(cert *x509.Certificate) string {
	sum := blake2b.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
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

func pause() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Press enter to continue")
	reader.ReadString('\n')
}
