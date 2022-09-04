package grpcoauth

import (
	"context"
	"encoding/base64"
	"strings"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthFunc func(ctx context.Context, creds *OAuthCredentials) (context.Context, error)

type OAuthCredentials struct {
	AccessToken  string
	ClientID     string
	ClientSecret string
}

func extractClientIDOrTokenFromContext(ctx context.Context) (*OAuthCredentials, error) {
	creds := &OAuthCredentials{}

	if token, err := auth.AuthFromMD(ctx, "bearer"); err == nil {
		creds.AccessToken = token
	}

	if val, err := auth.AuthFromMD(ctx, "basic"); err == nil {
		b, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return nil, status.Errorf(codes.Unauthenticated, "Basic auth invalid")
		}

		parts := strings.SplitN(string(b), ":", 2)

		if len(parts) != 2 {
			return nil, status.Errorf(codes.Unauthenticated, "Basic auth invalid")
		}

		creds.ClientID = parts[0]
		creds.ClientSecret = parts[1]
	}

	return creds, nil
}

func authFunc(f AuthFunc) auth.AuthFunc {
	return func(ctx context.Context) (context.Context, error) {
		creds, err := extractClientIDOrTokenFromContext(ctx)
		if err != nil {
			return nil, err
		}

		return f(ctx, creds)
	}
}

func StreamServerInterceptor(f AuthFunc) grpc.StreamServerInterceptor {
	return auth.StreamServerInterceptor(authFunc(f))
}

func UnaryServerInterceptor(f AuthFunc) grpc.UnaryServerInterceptor {
	return auth.UnaryServerInterceptor(authFunc(f))
}
