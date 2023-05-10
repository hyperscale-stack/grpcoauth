package grpcoauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type FakeStreamServer struct {
	ctx context.Context
}

func (f *FakeStreamServer) SetHeader(metadata.MD) error {
	return nil
}

func (f *FakeStreamServer) SendHeader(metadata.MD) error {
	return nil
}

func (f *FakeStreamServer) SetTrailer(metadata.MD) {
}

func (f *FakeStreamServer) Context() context.Context {
	return f.ctx
}

func (f *FakeStreamServer) SendMsg(m interface{}) error {
	return nil
}

func (f *FakeStreamServer) RecvMsg(m interface{}) error {
	return nil
}

func TestStreamServerInterceptor(t *testing.T) {
	authF := func(ctx context.Context, creds *OAuthCredentials) (context.Context, error) {
		assert.Equal(t, "foo", creds.ClientID)
		assert.Equal(t, "bar", creds.ClientSecret)

		return ctx, nil
	}

	fss := &FakeStreamServer{
		ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{
			"authorization": []string{"basic Zm9vOmJhcg=="},
		}),
	}

	err := StreamServerInterceptor(authF)(nil, fss, &grpc.StreamServerInfo{
		FullMethod: "/foo.bar",
	}, func(srv interface{}, stream grpc.ServerStream) error {

		return nil
	})
	assert.NoError(t, err)
}

func TestStreamServerInterceptorWithBadBasicAuthString(t *testing.T) {
	authF := func(ctx context.Context, creds *OAuthCredentials) (context.Context, error) {
		assert.Equal(t, "foo", creds.ClientID)
		assert.Equal(t, "bar", creds.ClientSecret)

		return ctx, nil
	}

	fss := &FakeStreamServer{
		ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{
			"authorization": []string{"basic ="},
		}),
	}

	err := StreamServerInterceptor(authF)(nil, fss, &grpc.StreamServerInfo{
		FullMethod: "/foo.bar",
	}, func(srv interface{}, stream grpc.ServerStream) error {

		return nil
	})

	assert.EqualError(t, err, "rpc error: code = Unauthenticated desc = Basic auth invalid")
}

func TestStreamServerInterceptorWithBadBase64BasicAuthString(t *testing.T) {
	authF := func(ctx context.Context, creds *OAuthCredentials) (context.Context, error) {
		assert.Equal(t, "foo", creds.ClientID)
		assert.Equal(t, "bar", creds.ClientSecret)

		return ctx, nil
	}

	fss := &FakeStreamServer{
		ctx: metadata.NewIncomingContext(context.Background(), metadata.MD{
			"authorization": []string{"basic YmFk"},
		}),
	}

	err := StreamServerInterceptor(authF)(nil, fss, &grpc.StreamServerInfo{
		FullMethod: "/foo.bar",
	}, func(srv interface{}, stream grpc.ServerStream) error {

		return nil
	})

	assert.EqualError(t, err, "rpc error: code = Unauthenticated desc = Basic auth invalid")
}
