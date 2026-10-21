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
	"time"

	pb "github.com/dmitrymack/go-password-manager/api/proto"
	"github.com/dmitrymack/go-password-manager/internal/client/secret"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Errors the commands react to.
var (
	ErrUnavailable    = errors.New("server unavailable")
	ErrSessionExpired = errors.New("session expired or invalid: run `gophkeeper login`")
	ErrNotFound       = errors.New("secret not found")
)

// maxMessageSize fits the largest secret (10 MB) plus overhead.
const maxMessageSize = 11 << 20

// Options configure the connection.
type Options struct {
	Address    string // host:port of the server
	CACertFile string // CA to verify the server with; empty means system CAs
	Plaintext  bool   // no TLS at all; for local development only
	Token      string // sent with secret calls; empty for register/login
}

// Client is a connection to the server.
type Client struct {
	conn    *grpc.ClientConn
	auth    pb.AuthServiceClient
	secrets pb.SecretServiceClient
	token   string
}

// Dial prepares a connection to the server. gRPC connects lazily, so an
// unreachable server shows up on the first call, not here.
func Dial(opts Options) (*Client, error) {
	creds, err := transportCredentials(opts)
	if err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(opts.Address,
		grpc.WithTransportCredentials(creds),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxMessageSize),
			grpc.MaxCallSendMsgSize(maxMessageSize),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", opts.Address, err)
	}

	return &Client{
		conn:    conn,
		auth:    pb.NewAuthServiceClient(conn),
		secrets: pb.NewSecretServiceClient(conn),
		token:   opts.Token,
	}, nil
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

// Sync returns secrets changed after since and the current revision.
func (c *Client) Sync(ctx context.Context, since int64) ([]secret.Info, int64, error) {
	resp, err := c.secrets.Sync(c.withToken(ctx), &pb.SyncRequest{SinceRevision: since})
	if err != nil {
		return nil, 0, convertSecretError(err)
	}

	changed := make([]secret.Info, 0, len(resp.GetChanged()))
	for _, info := range resp.GetChanged() {
		changed = append(changed, fromPB(info))
	}
	return changed, resp.GetRevision(), nil
}

// Get returns a secret with its data.
func (c *Client) Get(ctx context.Context, id string) (secret.Secret, error) {
	resp, err := c.secrets.Get(c.withToken(ctx), &pb.GetSecretRequest{Id: id})
	if err != nil {
		return secret.Secret{}, convertSecretError(err)
	}
	return secret.Secret{Info: fromPB(resp.GetInfo()), Data: resp.GetData()}, nil
}

// withToken adds the "authorization" header to an outgoing call.
func (c *Client) withToken(ctx context.Context) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.token)
}

// fromPB converts the API form of a secret's info.
func fromPB(info *pb.SecretInfo) secret.Info {
	return secret.Info{
		ID:        info.GetId(),
		Type:      secret.Type(info.GetType()),
		Name:      info.GetName(),
		Metadata:  info.GetMetadata(),
		Version:   info.GetVersion(),
		Revision:  info.GetRevision(),
		Deleted:   info.GetDeleted(),
		UpdatedAt: time.Unix(info.GetUpdatedAtUnix(), 0),
	}
}

// convertSecretError is convertError plus the errors specific to secret calls.
func convertSecretError(err error) error {
	switch status.Code(err) {
	case codes.Unauthenticated:
		return ErrSessionExpired
	case codes.NotFound:
		return ErrNotFound
	default:
		return convertError(err)
	}
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
