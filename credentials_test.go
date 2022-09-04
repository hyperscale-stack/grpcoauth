package grpcoauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"

	greeterv1 "github.com/hyperscale-stack/grpcoauth/gen/proto/go/greeter/v1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func Certificate(certPath string, keyPath string) (tls.Certificate, error) {
	crt, err := os.ReadFile(certPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read cert file: %w", err)
	}

	key, err := os.ReadFile(keyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("read key file: %w", err)
	}

	cert, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create key pair: %w", err)
	}

	return cert, nil
}

type fakeGreeterServer struct {
	sayHelloFn func(context.Context, *greeterv1.SayHelloRequest) (*greeterv1.SayHelloResponse, error)
}

func (gc *fakeGreeterServer) SayHello(ctx context.Context, in *greeterv1.SayHelloRequest) (*greeterv1.SayHelloResponse, error) {
	if gc.sayHelloFn != nil {
		return gc.sayHelloFn(ctx, in)
	}

	return nil, errors.New("fakeGreeterServer was not set up with a response - must set gc.sayHelloFn")
}

func TestPerRPCClientIDCredentials(t *testing.T) {
	var wg sync.WaitGroup

	authF := func(ctx context.Context, creds *OAuthCredentials) (context.Context, error) {
		assert.Equal(t, "foo", creds.ClientID)
		assert.Equal(t, "bar", creds.ClientSecret)

		return ctx, nil
	}

	ctx := context.Background()

	fgs := &fakeGreeterServer{}
	// Set up the fake greeter to return a canned message.
	fgs.sayHelloFn = func(ctx context.Context, in *greeterv1.SayHelloRequest) (*greeterv1.SayHelloResponse, error) {
		defer wg.Done()

		md, ok := metadata.FromIncomingContext(ctx)
		assert.True(t, ok)
		assert.Contains(t, md, "authorization")

		// Base64("foo:bar") = "Zm9vOmJhcg=="
		assert.Equal(t, "Basic Zm9vOmJhcg==", md["authorization"][0])

		return &greeterv1.SayHelloResponse{}, nil
	}

	l, err := net.Listen("tcp", "localhost:0") // IIRC 0 == "first available port"
	assert.NoError(t, err)

	cert, err := Certificate("./certs/server-cert.pem", "./certs/server-key.pem")
	assert.NoError(t, err)

	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewServerTLSFromCert(&cert)),
		grpc.UnaryInterceptor(UnaryServerInterceptor(authF)),
	}

	gsrv := grpc.NewServer(opts...)
	greeterv1.RegisterGreeterServer(gsrv, fgs)

	fakeGreeterAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err) // We're in a goroutine - we can't t.Fatal/t.Error.
		}
	}()

	crt, err := os.ReadFile("./certs/ca-cert.pem")
	assert.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(crt)

	creds := credentials.NewClientTLSFromCert(pool, "localhost")

	clientOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	conn, err := grpc.Dial(fakeGreeterAddr, clientOpts...)
	assert.NoError(t, err)

	defer conn.Close()

	gc := greeterv1.NewGreeterClient(conn)

	wg.Add(1)
	_, err = gc.SayHello(ctx, &greeterv1.SayHelloRequest{}, PerRPCClientIDCredentials("foo", "bar"))
	assert.NoError(t, err)

	wg.Wait()
}

func TestPerRPCTokenCredentials(t *testing.T) {
	var wg sync.WaitGroup

	authF := func(ctx context.Context, creds *OAuthCredentials) (context.Context, error) {
		assert.Equal(t, "feadbb35-c2be-4529-b2a6-19109e07eaa3", creds.AccessToken)

		return ctx, nil
	}

	ctx := context.Background()

	fgs := &fakeGreeterServer{}
	// Set up the fake greeter to return a canned message.
	fgs.sayHelloFn = func(ctx context.Context, in *greeterv1.SayHelloRequest) (*greeterv1.SayHelloResponse, error) {
		defer wg.Done()

		md, ok := metadata.FromIncomingContext(ctx)
		assert.True(t, ok)
		assert.Contains(t, md, "authorization")

		assert.Equal(t, "Bearer feadbb35-c2be-4529-b2a6-19109e07eaa3", md["authorization"][0])

		return &greeterv1.SayHelloResponse{}, nil
	}

	l, err := net.Listen("tcp", "localhost:0") // IIRC 0 == "first available port"
	assert.NoError(t, err)

	cert, err := Certificate("./certs/server-cert.pem", "./certs/server-key.pem")
	assert.NoError(t, err)

	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewServerTLSFromCert(&cert)),
		grpc.UnaryInterceptor(UnaryServerInterceptor(authF)),
	}

	gsrv := grpc.NewServer(opts...)
	greeterv1.RegisterGreeterServer(gsrv, fgs)

	fakeGreeterAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err) // We're in a goroutine - we can't t.Fatal/t.Error.
		}
	}()

	crt, err := os.ReadFile("./certs/ca-cert.pem")
	assert.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(crt)

	creds := credentials.NewClientTLSFromCert(pool, "localhost")

	clientOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
	}

	conn, err := grpc.Dial(fakeGreeterAddr, clientOpts...)
	assert.NoError(t, err)

	defer conn.Close()

	gc := greeterv1.NewGreeterClient(conn)

	wg.Add(1)
	_, err = gc.SayHello(ctx, &greeterv1.SayHelloRequest{}, PerRPCTokenCredentials("feadbb35-c2be-4529-b2a6-19109e07eaa3"))
	assert.NoError(t, err)

	wg.Wait()
}

func TestWithPerRPCClientIDCredentials(t *testing.T) {
	var wg sync.WaitGroup

	ctx := context.Background()

	fgs := &fakeGreeterServer{}
	// Set up the fake greeter to return a canned message.
	fgs.sayHelloFn = func(ctx context.Context, in *greeterv1.SayHelloRequest) (*greeterv1.SayHelloResponse, error) {
		defer wg.Done()

		md, ok := metadata.FromIncomingContext(ctx)
		assert.True(t, ok)
		assert.Contains(t, md, "authorization")

		// Base64("foo:bar") = "Zm9vOmJhcg=="
		assert.Equal(t, "Basic Zm9vOmJhcg==", md["authorization"][0])

		return &greeterv1.SayHelloResponse{}, nil
	}

	l, err := net.Listen("tcp", "localhost:0") // IIRC 0 == "first available port"
	assert.NoError(t, err)

	cert, err := Certificate("./certs/server-cert.pem", "./certs/server-key.pem")
	assert.NoError(t, err)

	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewServerTLSFromCert(&cert)),
	}

	gsrv := grpc.NewServer(opts...)
	greeterv1.RegisterGreeterServer(gsrv, fgs)

	fakeGreeterAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err) // We're in a goroutine - we can't t.Fatal/t.Error.
		}
	}()

	crt, err := os.ReadFile("./certs/ca-cert.pem")
	assert.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(crt)

	creds := credentials.NewClientTLSFromCert(pool, "localhost")

	clientOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		WithPerRPCClientIDCredentials("foo", "bar"),
	}

	conn, err := grpc.Dial(fakeGreeterAddr, clientOpts...)
	assert.NoError(t, err)

	defer conn.Close()

	gc := greeterv1.NewGreeterClient(conn)

	wg.Add(1)
	_, err = gc.SayHello(ctx, &greeterv1.SayHelloRequest{})
	assert.NoError(t, err)

	wg.Wait()
}

func TestWithPerRPCTokenCredentials(t *testing.T) {
	var wg sync.WaitGroup

	ctx := context.Background()

	fgs := &fakeGreeterServer{}
	// Set up the fake greeter to return a canned message.
	fgs.sayHelloFn = func(ctx context.Context, in *greeterv1.SayHelloRequest) (*greeterv1.SayHelloResponse, error) {
		defer wg.Done()

		md, ok := metadata.FromIncomingContext(ctx)
		assert.True(t, ok)
		assert.Contains(t, md, "authorization")

		assert.Equal(t, "Bearer feadbb35-c2be-4529-b2a6-19109e07eaa3", md["authorization"][0])

		return &greeterv1.SayHelloResponse{}, nil
	}

	l, err := net.Listen("tcp", "localhost:0") // IIRC 0 == "first available port"
	assert.NoError(t, err)

	cert, err := Certificate("./certs/server-cert.pem", "./certs/server-key.pem")
	assert.NoError(t, err)

	opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewServerTLSFromCert(&cert)),
	}

	gsrv := grpc.NewServer(opts...)
	greeterv1.RegisterGreeterServer(gsrv, fgs)

	fakeGreeterAddr := l.Addr().String()
	go func() {
		if err := gsrv.Serve(l); err != nil {
			panic(err) // We're in a goroutine - we can't t.Fatal/t.Error.
		}
	}()

	crt, err := os.ReadFile("./certs/ca-cert.pem")
	assert.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(crt)

	creds := credentials.NewClientTLSFromCert(pool, "localhost")

	clientOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(creds),
		WithPerRPCTokenCredentials("feadbb35-c2be-4529-b2a6-19109e07eaa3"),
	}

	conn, err := grpc.Dial(fakeGreeterAddr, clientOpts...)
	assert.NoError(t, err)

	defer conn.Close()

	gc := greeterv1.NewGreeterClient(conn)

	wg.Add(1)
	_, err = gc.SayHello(ctx, &greeterv1.SayHelloRequest{})
	assert.NoError(t, err)

	wg.Wait()
}
