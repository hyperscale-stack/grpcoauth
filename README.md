# Hyperscale gRPC OAuth [![Last release](https://img.shields.io/github/release/hyperscale-stack/grpcoauth.svg)](https://github.com/hyperscale-stack/grpcoauth/releases/latest) [![Documentation](https://godoc.org/github.com/hyperscale-stack/grpcoauth?status.svg)](https://godoc.org/github.com/hyperscale-stack/grpcoauth)

[![Go Report Card](https://goreportcard.com/badge/github.com/hyperscale-stack/grpcoauth)](https://goreportcard.com/report/github.com/hyperscale-stack/grpcoauth)

| Branch | Status                                                                                                                                                                           | Coverage                                                                                                                                                     |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| master | [![Build Status](https://github.com/hyperscale-stack/grpcoauth/workflows/Go/badge.svg?branch=master)](https://github.com/hyperscale-stack/grpcoauth/actions?query=workflow%3AGo) | [![Coveralls](https://img.shields.io/coveralls/hyperscale-stack/grpcoauth/master.svg)](https://coveralls.io/github/hyperscale-stack/grpcoauth?branch=master) |

The Hyperscale grpcoauth library provides a simple gRPC credentials.PerRPCCredentials with OAuth

## Example

```go
package main

import (
    "github.com/hyperscale-stack/grpcoauth"
)

func main() {
    cert := ...

    authF := func(ctx context.Context, creds *OAuthCredentials) (context.Context, error) {
		// implements your business logic for authenticate
        // creds contains AccessToken or ClientID and ClientSecret

		return ctx, nil
	}

    opts := []grpc.ServerOption{
		grpc.Creds(credentials.NewServerTLSFromCert(&cert)),
		grpc.UnaryInterceptor(UnaryServerInterceptor(authF)),
	}

	gsrv := grpc.NewServer(opts...)


    // init gRPC Dial and init service
    greeter := ...

    _, err = greeter.SayHello(ctx, &greeterv1.SayHelloRequest{}, grpcoauth.PerRPCTokenCredentials("feadbb35-c2be-4529-b2a6-19109e07eaa3"))
}

```

## License

Hyperscale grpcoauth is licensed under [the MIT license](LICENSE.md).
