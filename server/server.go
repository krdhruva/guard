/*
Copyright The Guard Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"path/filepath"
	"reflect"
	"time"

	"github.com/appscode/go/ntp"
	"github.com/appscode/go/signals"
	v "github.com/appscode/go/version"
	"github.com/appscode/guard/auth/providers/token"
	"github.com/appscode/guard/authz/providers/azure"
	"github.com/appscode/guard/authz/providers/azure/data"
	"github.com/appscode/pat"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"
	"kmodules.xyz/client-go/meta"
	"kmodules.xyz/client-go/tools/fsnotify"
)

type Server struct {
	RecommendedOptions *RecommendedOptions
	TokenAuthenticator *token.Authenticator
	Store              *data.DataStore
}

func (s *Server) AddFlags(fs *pflag.FlagSet) {
	s.RecommendedOptions.AddFlags(fs)
}

func (s Server) ListenAndServe() {

	fmt.Println("KD: testing logger format")
	if errs := s.RecommendedOptions.Validate(); errs != nil {
		glog.Fatal(errs)
	}

	if s.RecommendedOptions.NTP.Enabled() {
		ticker := time.NewTicker(s.RecommendedOptions.NTP.Interval)
		go func() {
			for range ticker.C {
				if err := ntp.CheckSkewFromServer(s.RecommendedOptions.NTP.NTPServer, s.RecommendedOptions.NTP.MaxClodkSkew); err != nil {
					glog.Fatal(err)
				}
			}
		}()
	}

	if s.RecommendedOptions.Token.AuthFile != "" {
		s.TokenAuthenticator = token.New(s.RecommendedOptions.Token)

		err := s.TokenAuthenticator.Configure()
		if err != nil {
			glog.Fatalln(err)
		}
		if meta.PossiblyInCluster() {
			w := fsnotify.Watcher{
				WatchDir: filepath.Dir(s.RecommendedOptions.Token.AuthFile),
				Reload: func() error {
					return s.TokenAuthenticator.Configure()
				},
			}
			stopCh := signals.SetupSignalHandler()
			err = w.Run(stopCh)
			if err != nil {
				glog.Fatal(err)
			}
		}
	}

	// loading file read related data
	if err := s.RecommendedOptions.LDAP.Configure(); err != nil {
		glog.Fatal(err)
	}
	if err := s.RecommendedOptions.Google.Configure(); err != nil {
		glog.Fatal(err)
	}

	/*
		Ref:
		 - http://www.levigross.com/2015/11/21/mutual-tls-authentication-in-go/
		 - https://blog.cloudflare.com/exposing-go-on-the-internet/
		 - http://www.bite-code.com/2015/06/25/tls-mutual-auth-in-golang/
		 - http://www.hydrogen18.com/blog/your-own-pki-tls-golang.html
	*/
	caCert, err := ioutil.ReadFile(s.RecommendedOptions.SecureServing.CACertFile)
	if err != nil {
		glog.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	ok := caCertPool.AppendCertsFromPEM(caCert)
	if !ok {
		glog.Fatal("Failed to add CA cert in CertPool for guard server")
	}

	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		SessionTicketsDisabled:   true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, // Go 1.8 only
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,   // Go 1.8 only
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		// ClientAuth: tls.VerifyClientCertIfGiven needed to pass healthz check
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  caCertPool,
		NextProtos: []string{"h2", "http/1.1"},
	}
	tlsConfig.BuildNameToCertificate()

	m := pat.New()

	// Instrument the handlers with all the metrics, injecting the "handler" label by currying.
	// ref:
	// - https://godoc.org/github.com/prometheus/client_golang/prometheus/promhttp#example-InstrumentHandlerDuration
	// - https://github.com/brancz/prometheus-example-app/blob/master/main.go#L44:28
	handler := promhttp.InstrumentHandlerInFlight(inFlightGauge,
		promhttp.InstrumentHandlerDuration(duration.MustCurryWith(prometheus.Labels{"handler": "tokenreviews"}),
			promhttp.InstrumentHandlerCounter(counter,
				promhttp.InstrumentHandlerResponseSize(responseSize.MustCurryWith(prometheus.Labels{"handler": "tokenreviews"}),&s),
			),
		),
	)
	glog.Infof("Type of auth handler:%s", reflect.TypeOf(handler).String())
	m.Post("/tokenreviews", handler)
	m.Get("/metrics", promhttp.Handler())
	m.Get("/healthz", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("x-content-type-options", "nosniff")
		err := json.NewEncoder(w).Encode(v.Version)
		if err != nil {
			glog.Fatal(err)
		}
	}))

	glog.Infof("Type of auth handler:%s", reflect.TypeOf(s.Authzhandler).String())
	if len(s.RecommendedOptions.AuthzProvider.Providers) > 0 {
		m.Post("/subjectaccessreviews", http.HandlerFunc(s.Authzhandler))

		if s.RecommendedOptions.AuthzProvider.Has(azure.OrgType) {
			options := data.DefaultOptions
			s.Store, err = data.NewDataStore(options)
			if s.Store == nil || err != nil {
				glog.V(10).Infof("Error in cache. %v %s", s.Store==nil, err.Error())
				glog.Fatalln(err)
				panic(err)
			}
		}
	}

	srv := &http.Server{
		Addr:         s.RecommendedOptions.SecureServing.SecureAddr,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Handler:      m,
		TLSConfig:    tlsConfig,
	}
	glog.Fatalln(srv.ListenAndServeTLS(s.RecommendedOptions.SecureServing.CertFile, s.RecommendedOptions.SecureServing.KeyFile))
}
