package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

type serverTLSManager struct {
	srvCertPath string
	srvKeyPath  string

	mtx            sync.Mutex
	srvCert        *tls.Certificate
	srvCertModTime time.Time
	srvKeyModTime  time.Time
}

func (m *serverTLSManager) getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	statCert, err := os.Stat(m.srvCertPath)
	if err != nil {
		return nil, err
	}
	statKey, err := os.Stat(m.srvKeyPath)
	if err != nil {
		return nil, err
	}

	if m.srvCert == nil || !statCert.ModTime().Equal(m.srvCertModTime) || !statKey.ModTime().Equal(m.srvKeyModTime) {
		cert, err := tls.LoadX509KeyPair(m.srvCertPath, m.srvKeyPath)
		if err != nil {
			return nil, err
		}
		m.srvCertModTime = statCert.ModTime()
		m.srvKeyModTime = statKey.ModTime()
		m.srvCert = &cert
	}
	return m.srvCert, nil
}

func getTLSConfig(certPath, keyPath, clientCA string, logger log.Logger) (*tls.Config, error) {
	if keyPath == "" && certPath == "" {
		if clientCA != "" {
			return nil, errors.New("when a client CA is used a server key and certificate must also be provided")
		}
		level.Info(logger).Log("msg", "disabled TLS, key and cert must be set to enable")
		return nil, nil
	}

	level.Info(logger).Log("msg", "enabling server side TLS")
	if keyPath == "" || certPath == "" {
		return nil, errors.New("both server key and certificate must be provided")
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
	// Certificate is loaded during server startup to check for any errors.
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	mngr := &serverTLSManager{
		srvCertPath: certPath,
		srvKeyPath:  keyPath,
		srvCert:     &certificate,
	}
	tlsCfg.GetCertificate = mngr.getCertificate

	if clientCA != "" {
		caPEM, err := os.ReadFile(filepath.Clean(clientCA))
		if err != nil {
			return nil, fmt.Errorf("reading client CA: %s", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("building client CA: %s", err)
		}
		tlsCfg.ClientCAs = certPool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
		level.Info(logger).Log("msg", "server TLS client verification enabled")
	}

	return tlsCfg, nil
}
