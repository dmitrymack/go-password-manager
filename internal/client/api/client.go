// Package api is the client side of the gRPC API: it connects to the
// server and turns gRPC errors into readable ones.
package api

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	pb "github.com/dmitrymack/go-password-manager/api/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// ErrUnavailable is returned when the server can't be reached.
var ErrUnavailable = errors.New("server unavailable")

// Options configure the connection.
type Options struct {
	Address    string // host:port of the server
	CACertFile string // CA to verify the server with; empty means system CAs
	Plaintext  bool   // no TLS at all; for local development only
}

// Client is a connection to the server.
type Client struct {
	conn *grpc.ClientConn
	auth pb.AuthServiceClient
}

// Dial prepares a connection to the server. gRPC connects lazily, so an
// unreachable server shows up on the first call, not here.
func Dial(opts Options) (*Client, error) {
	creds, err := transportCredentials(opts)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(opts.Address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", opts.Address, err)
	}

	return &Client{conn: conn, auth: pb.NewAuthServiceClient(conn)}, nil
}

// transportCredentials picks plaintext, TLS with a custom CA, or TLS with
// the system CAs.
func transportCredentials(opts Options) (credentials.TransportCredentials, error) {
	if opts.Plaintext {
		return insecure.NewCredentials(), nil
	}

	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.CACertFile != "" {
		pem, err := os.ReadFile(opts.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA certificate: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", opts.CACertFile)
		}
		cfg.RootCAs = pool
	}
	return credentials.NewTLS(cfg), nil
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Register creates a user and returns their token.
func (c *Client) Register(ctx context.Context, login, password string) (string, error) {
	resp, err := c.auth.Register(ctx, &pb.Credentials{Login: login, Password: password})
	if err != nil {
		return "", convertError(err)
	}
	return resp.GetToken(), nil
}

// Login authenticates and returns a token.
func (c *Client) Login(ctx context.Context, login, password string) (string, error) {
	resp, err := c.auth.Login(ctx, &pb.Credentials{Login: login, Password: password})
	if err != nil {
		return "", convertError(err)
	}
	return resp.GetToken(), nil
}

// convertError turns a gRPC status into an error with just its message,
// and connection problems into ErrUnavailable.
func convertError(err error) error {
	st := status.Convert(err)
	if st.Code() == codes.Unavailable || st.Code() == codes.DeadlineExceeded {
		return fmt.Errorf("%w: %s", ErrUnavailable, st.Message())
	}
	return errors.New(st.Message())
}
