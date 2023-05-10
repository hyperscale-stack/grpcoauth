package grpcoauth

import (
	"encoding/base64"

	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
)

func newOAuth2ClientIDCredentials(clientID string, secret string) credentials.PerRPCCredentials {
	token := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + secret))

	return &oauth.TokenSource{
		TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: token,
			TokenType:   "basic",
		}),
	}
}

func newOAuth2AccessTokenCredentials(token string) credentials.PerRPCCredentials {
	return &oauth.TokenSource{
		TokenSource: oauth2.StaticTokenSource(&oauth2.Token{
			AccessToken: token,
		}),
	}
}

// PerRPCClientIDCredentials returns a CallOption that sets credentials.PerRPCCredentials
// with OAuth2 client_id and secret for a call.
func PerRPCClientIDCredentials(clientID string, secret string) grpc.CallOption {
	return grpc.PerRPCCredentials(newOAuth2ClientIDCredentials(clientID, secret))
}

// PerRPCTokenCredentials returns a CallOption that sets credentials.PerRPCCredentials
// with OAuth2 token for a call.
func PerRPCTokenCredentials(token string) grpc.CallOption {
	return grpc.PerRPCCredentials(newOAuth2AccessTokenCredentials(token))
}

// WithPerRPCClientIDCredentials returns a DialOption which sets OAuth2 client_id
// and secret credentials and places auth state on each outbound RPC.
func WithPerRPCClientIDCredentials(clientID string, secret string) grpc.DialOption {
	return grpc.WithPerRPCCredentials(newOAuth2ClientIDCredentials(clientID, secret))
}

// WithPerRPCTokenCredentials returns a DialOption which sets OAuth2 token
// credentials and places auth state on each outbound RPC.
func WithPerRPCTokenCredentials(token string) grpc.DialOption {
	return grpc.WithPerRPCCredentials(newOAuth2AccessTokenCredentials(token))
}
