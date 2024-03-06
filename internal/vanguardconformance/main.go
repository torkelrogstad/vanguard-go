package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"buf.build/gen/go/connectrpc/conformance/connectrpc/go/connectrpc/conformance/v1/conformancev1connect"
	conformancev1 "buf.build/gen/go/connectrpc/conformance/protocolbuffers/go/connectrpc/conformance/v1"
	"connectrpc.com/vanguard"
	"google.golang.org/protobuf/proto"
)

const (
	DefaultReferenceServerName = "referenceserver"
)

func getOrDefault(env, def string) string {
	if value := os.Getenv(env); value != "" {
		return value
	}
	return def
}

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			fmt.Println("Received signal:", sig)
			cancel()
			time.Sleep(1 * time.Second)
			fmt.Println("exit")
			os.Exit(1)
		}
	}()
	if err := Run(ctx, os.Args, os.Stdin, os.Stdout, os.Stderr); err != nil {
		log.Fatalf("an error occurred running the conformance server: %s", err.Error())
	}
}

// Run runs the conformance server as a proxy between the conformance test runner and the actual
// implementation of the reference server.
func Run(ctx context.Context, args []string, osStdin io.ReadCloser, osStdout, osStderr io.WriteCloser) error {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	referenceServerName := flags.String("server", getOrDefault("REFERENCE_SERVER_NAME", DefaultReferenceServerName), "The name of the reference server to run")

	fmt.Fprintln(osStderr, "Starting conformance server")
	defer fmt.Fprintln(osStderr, "Conformance server done")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}

	var req conformancev1.ServerCompatRequest
	if err := decodeMessage(osStdin, &req); err != nil {
		return err
	}
	fmt.Fprintf(osStderr, "req: %s\n", &req)

	// Maybe mutate the input config here.
	var (
		stdin            bytes.Buffer
		stdoutR, stdoutW = io.Pipe()
		stdout           bytes.Buffer
		stderr           bytes.Buffer
		execErr          error
		execDone         = make(chan struct{})
	)
	scheme := "http"
	var tlsConfig *tls.Config
	if req.UseTls {
		scheme = "https"
		creds := req.GetServerCreds()
		if creds == nil {
			return fmt.Errorf("missing server creds")
		}
		clientCertMode := tls.NoClientCert
		if len(req.ClientTlsCert) > 0 {
			clientCertMode = tls.RequireAndVerifyClientCert
		}
		var err error
		tlsConfig, err = newServerTLSConfig(
			creds.Cert, creds.Key, clientCertMode, req.ClientTlsCert,
		)
		if err != nil {
			return fmt.Errorf("failed to create server TLS config: %w", err)
		}

		// Zero config.
		req.UseTls = false
		req.ServerCreds = nil
		req.ClientTlsCert = nil
	}
	if err := encodeMessage(&stdin, &req); err != nil {
		return err
	}
	go func() {
		fmt.Fprintf(osStderr, "Running reference server: %s\n", *referenceServerName)
		defer fmt.Fprintf(osStderr, "Reference server done: %s\n", *referenceServerName)
		cmd := exec.CommandContext(ctx, *referenceServerName)
		cmd.Stdin = &stdin
		cmd.Stdout = io.MultiWriter(stdoutW, &stdout)
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			execErr = fmt.Errorf("%s: %s", err, stderr.String())
		}
		close(execDone)
	}()

	var resp conformancev1.ServerCompatResponse
	if err := decodeMessage(stdoutR, &resp); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	fmt.Fprintf(osStderr, "resp: %s\n", &resp)
	select {
	case <-execDone:
		return fmt.Errorf("reference server exited early: %w", execErr)
	default:
	}
	log.Println("Creating proxy server")

	refURL := &url.URL{
		Scheme: scheme,
		Host:   resp.Host + ":" + strconv.Itoa(int(resp.Port)),
	}

	// Create a server that proxies requests to the reference server.
	proxyHandler := httputil.NewSingleHostReverseProxy(refURL)

	opts := []vanguard.ServiceOption{
		vanguard.WithTargetProtocols(vanguard.ProtocolConnect),
		vanguard.WithTargetCodecs(vanguard.CodecJSON),
		vanguard.WithNoTargetCompression(),
	}
	services := []*vanguard.Service{
		vanguard.NewService(
			conformancev1connect.ConformanceServiceName,
			proxyHandler,
			opts...,
		),
	}
	handler, err := vanguard.NewTranscoder(services)
	if err != nil {
		return err
	}
	logHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println("logHandler", r.Method, r.URL)
		handler.ServeHTTP(w, r)
	})

	proxyServer := httptest.NewUnstartedServer(logHandler)
	proxyServer.TLS = tlsConfig
	switch req.HttpVersion {
	case conformancev1.HTTPVersion_HTTP_VERSION_1:
		// nothing
	case conformancev1.HTTPVersion_HTTP_VERSION_2:
		proxyServer.EnableHTTP2 = true
	case conformancev1.HTTPVersion_HTTP_VERSION_3:
		return fmt.Errorf("HTTP/3 is not supported")
	default:
		return fmt.Errorf("unknown HTTP version: %v", req.HttpVersion)
	}
	proxyServer.Start()
	defer proxyServer.Close()

	addr := proxyServer.Listener.Addr()

	host, port, ok := strings.Cut(addr.String(), ":")
	if !ok {
		return fmt.Errorf("failed to parse address: %s", addr)
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("failed to parse port: %s", port)
	}
	resp.Host = host
	resp.Port = uint32(portInt)

	if err := encodeMessage(osStdout, &resp); err != nil {
		return fmt.Errorf("failed to encode response: %w", err)
	}

	select {
	case <-execDone:
		fmt.Println("exec done")
		return execErr
	case <-ctx.Done():
		fmt.Println("ctx done")
		return ctx.Err()
	}
}

func decodeMessage(input io.Reader, msg proto.Message) error {
	var head [4]byte
	if _, err := io.ReadFull(input, head[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(head[:])
	buf, err := io.ReadAll(io.LimitReader(input, int64(size)))
	if err != nil {
		return err
	}
	return proto.Unmarshal(buf, msg)
}

func encodeMessage(output io.Writer, msg proto.Message) error {
	b, err := proto.Marshal(msg)
	if err != nil {
		return err
	}
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], uint32(len(b)))
	if _, err := output.Write(head[:]); err != nil {
		return err
	}
	if _, err = output.Write(b); err != nil {
		return err
	}
	return nil
}

func newServerTLSConfig(
	cert, key []byte,
	clientCertMode tls.ClientAuthType,
	clientCACert []byte,
) (*tls.Config, error) {
	certificate, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, err
	}
	if clientCertMode != tls.NoClientCert && len(clientCACert) == 0 {
		return nil, fmt.Errorf("clientCertMode indicates client certs supported but CACert is empty")
	}
	var caCertPool *x509.CertPool
	if len(clientCACert) > 0 {
		caCertPool = x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(clientCACert) {
			return nil, fmt.Errorf("failed to parse client CA cert from given data")
		}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientCAs:    caCertPool,
		ClientAuth:   clientCertMode,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
