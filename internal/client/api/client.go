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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Errors the commands react to.
var (
	ErrUnavailable    = errors.New("server unavailable")
	ErrSessionExpired = errors.New("session expired or invalid: run `gophkeeper login`")
	ErrNotFound       = errors.New("secret not found")
	ErrConflict       = errors.New("secret was changed on another device: run the command again")
)

// maxMessageSize fits the largest secret (10 MB) plus overhead.
const maxMessageSize = 11 << 20

// retryCreate makes gRPC resend Create if the server was unreachable.
// Safe: the request carries the secret's ID, so a repeat can't duplicate it.
const retryCreate = `{"methodConfig": [{
	"name": [{"service": "gophkeeper.SecretService", "method": "Create"}],
	"retryPolicy": {
		"maxAttempts": 3,
		"initialBackoff": "0.5s",
		"maxBackoff": "2s",
		"backoffMultiplier": 2,
		"retryableStatusCodes": ["UNAVAILABLE"]
	}
}]}`

// Options configure the connection.
type Options struct {
	Address    string // host:port of the server
	CACertFile string // CA to verify the server with; empty means system CAs
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
		grpc.WithDefaultServiceConfig(retryCreate),
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

// transportCredentials sets up TLS with a custom CA or the system CAs.
func transportCredentials(opts Options) (credentials.TransportCredentials, error) {
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
	resp, err := c.auth.Register(ctx, credentialsPB(login, password))
	if err != nil {
		return "", convertError(err)
	}
	return resp.GetToken(), nil
}

// Login authenticates and returns a token.
func (c *Client) Login(ctx context.Context, login, password string) (string, error) {
	resp, err := c.auth.Login(ctx, credentialsPB(login, password))
	if err != nil {
		return "", convertError(err)
	}
	return resp.GetToken(), nil
}

// Sync returns secrets changed after since and the current revision.
func (c *Client) Sync(ctx context.Context, since int64) ([]secret.Info, int64, error) {
	resp, err := c.secrets.Sync(c.withToken(ctx), pb.SyncRequest_builder{SinceRevision: since}.Build())
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
	resp, err := c.secrets.Get(c.withToken(ctx), pb.GetSecretRequest_builder{Id: id}.Build())
	if err != nil {
		return secret.Secret{}, convertSecretError(err)
	}
	return secret.Secret{Info: fromPB(resp.GetInfo()), Data: resp.GetData()}, nil
}

// Create stores a new secret; s.ID must be a new UUID. If an earlier
// attempt already stored it (ALREADY_EXISTS), that counts as success.
func (c *Client) Create(ctx context.Context, s secret.Secret) (secret.Info, error) {
	resp, err := c.secrets.Create(c.withToken(ctx), pb.CreateSecretRequest_builder{
		Id:       s.ID,
		Type:     pb.SecretType(s.Type), //nolint:gosec // types are 1-4
		Name:     s.Name,
		Metadata: s.Metadata,
		Data:     s.Data,
	}.Build())
	if status.Code(err) == codes.AlreadyExists {
		return s.Info, nil
	}
	if err != nil {
		return secret.Info{}, convertSecretError(err)
	}
	return fromPB(resp), nil
}

// Update replaces a secret's name, metadata and data; s.Version must be
// the version the change is based on.
func (c *Client) Update(ctx context.Context, s secret.Secret) (secret.Info, error) {
	resp, err := c.secrets.Update(c.withToken(ctx), pb.UpdateSecretRequest_builder{
		Id:       s.ID,
		Version:  s.Version,
		Name:     s.Name,
		Metadata: s.Metadata,
		Data:     s.Data,
	}.Build())
	if err != nil {
		return secret.Info{}, convertSecretError(err)
	}
	return fromPB(resp), nil
}

// Delete deletes a secret.
func (c *Client) Delete(ctx context.Context, id string) error {
	_, err := c.secrets.Delete(c.withToken(ctx), pb.DeleteSecretRequest_builder{Id: id}.Build())
	return convertSecretError(err)
}

// credentialsPB builds the request of Register and Login.
func credentialsPB(login, password string) *pb.Credentials {
	return pb.Credentials_builder{Login: login, Password: password}.Build()
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
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.Unauthenticated:
		return ErrSessionExpired
	case codes.NotFound:
		return ErrNotFound
	case codes.Aborted:
		return ErrConflict
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
