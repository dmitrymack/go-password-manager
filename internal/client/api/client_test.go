package api

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/dmitrymack/go-password-manager/api/proto"
	"github.com/dmitrymack/go-password-manager/internal/client/secret"
	"github.com/dmitrymack/go-password-manager/internal/testcerts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeAuthServer accepts only the password "right".
type fakeAuthServer struct {
	pb.UnimplementedAuthServiceServer
}

func (fakeAuthServer) Register(_ context.Context, req *pb.Credentials) (*pb.AuthResponse, error) {
	return pb.AuthResponse_builder{Token: "reg-" + req.GetLogin()}.Build(), nil
}

func (fakeAuthServer) Login(_ context.Context, req *pb.Credentials) (*pb.AuthResponse, error) {
	if req.GetPassword() != "right" {
		return nil, status.Error(codes.Unauthenticated, "invalid login or password")
	}
	return pb.AuthResponse_builder{Token: "login-" + req.GetLogin()}.Build(), nil
}

// fakeSecretServer accepts only the token "good".
type fakeSecretServer struct {
	pb.UnimplementedSecretServiceServer
}

func checkToken(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	if v := md.Get("authorization"); len(v) == 0 || v[0] != "Bearer good" {
		return status.Error(codes.Unauthenticated, "invalid token")
	}
	return nil
}

var testInfo = pb.SecretInfo_builder{
	Id: "id1", Type: pb.SecretType_SECRET_TYPE_CARD, Name: "visa",
	Metadata: map[string]string{"bank": "x"}, Version: 2, Revision: 3, UpdatedAtUnix: 1700000000,
}.Build()

func (fakeSecretServer) Sync(ctx context.Context, req *pb.SyncRequest) (*pb.SyncResponse, error) {
	if err := checkToken(ctx); err != nil {
		return nil, err
	}
	return pb.SyncResponse_builder{Changed: []*pb.SecretInfo{testInfo}, Revision: req.GetSinceRevision() + 1}.Build(), nil
}

func (fakeSecretServer) Get(ctx context.Context, req *pb.GetSecretRequest) (*pb.Secret, error) {
	if err := checkToken(ctx); err != nil {
		return nil, err
	}
	if req.GetId() != "id1" {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	return pb.Secret_builder{Info: testInfo, Data: []byte("data")}.Build(), nil
}

func (fakeSecretServer) Create(ctx context.Context, req *pb.CreateSecretRequest) (*pb.SecretInfo, error) {
	if err := checkToken(ctx); err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name must be 1-255 characters")
	}
	if req.GetId() == "stored-before" {
		return nil, status.Error(codes.AlreadyExists, "secret already exists")
	}
	return pb.SecretInfo_builder{Id: req.GetId(), Type: req.GetType(), Name: req.GetName(), Version: 1}.Build(), nil
}

func (fakeSecretServer) Update(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.SecretInfo, error) {
	if err := checkToken(ctx); err != nil {
		return nil, err
	}
	if req.GetVersion() != 2 {
		return nil, status.Error(codes.Aborted, "version conflict")
	}
	return pb.SecretInfo_builder{Id: req.GetId(), Name: req.GetName(), Version: 3}.Build(), nil
}

func (fakeSecretServer) Delete(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.SecretInfo, error) {
	if err := checkToken(ctx); err != nil {
		return nil, err
	}
	if req.GetId() != "id1" {
		return nil, status.Error(codes.NotFound, "secret not found")
	}
	return pb.SecretInfo_builder{Id: "id1", Deleted: true}.Build(), nil
}

// startServer runs the fake servers over TLS on a free port; it returns
// options to dial them with.
func startServer(t *testing.T, token string) Options {
	t.Helper()

	certs := testcerts.Generate(t)
	creds, err := credentials.NewServerTLSFromFile(certs.Cert, certs.Key)
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterAuthServiceServer(srv, fakeAuthServer{})
	pb.RegisterSecretServiceServer(srv, fakeSecretServer{})
	go srv.Serve(lis) //nolint:errcheck // returns when the test stops the server
	t.Cleanup(srv.Stop)

	return Options{Address: lis.Addr().String(), CACertFile: certs.CA, Token: token}
}

func TestClientAuth(t *testing.T) {
	c, err := Dial(startServer(t, ""))
	require.NoError(t, err)
	defer c.Close()

	ctx := context.Background()

	token, err := c.Register(ctx, "alice", "any")
	require.NoError(t, err)
	assert.Equal(t, "reg-alice", token)

	token, err = c.Login(ctx, "alice", "right")
	require.NoError(t, err)
	assert.Equal(t, "login-alice", token)

	_, err = c.Login(ctx, "alice", "wrong")
	assert.EqualError(t, err, "invalid login or password")
}

func TestClientUnavailable(t *testing.T) {
	// Nothing listens on this port: take a free one and close it.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := lis.Addr().String()
	require.NoError(t, lis.Close())

	c, err := Dial(Options{Address: addr})
	require.NoError(t, err)
	defer c.Close()

	_, err = c.Login(context.Background(), "alice", "right")
	assert.ErrorIs(t, err, ErrUnavailable)
}

func TestDialCACert(t *testing.T) {
	_, err := Dial(Options{Address: "localhost:1", CACertFile: "missing.crt"})
	assert.Error(t, err)

	notPEM := filepath.Join(t.TempDir(), "ca.crt")
	require.NoError(t, os.WriteFile(notPEM, []byte("not a certificate"), 0o600))
	_, err = Dial(Options{Address: "localhost:1", CACertFile: notPEM})
	assert.Error(t, err)

	c, err := Dial(Options{Address: "localhost:1"}) // system CAs
	require.NoError(t, err)
	assert.NoError(t, c.Close())
}

func TestClientSecrets(t *testing.T) {
	opts := startServer(t, "good")
	ctx := context.Background()

	c, err := Dial(opts)
	require.NoError(t, err)
	defer c.Close()

	wantInfo := secret.Info{
		ID: "id1", Type: secret.TypeCard, Name: "visa", Metadata: map[string]string{"bank": "x"},
		Version: 2, Revision: 3, UpdatedAt: time.Unix(1700000000, 0),
	}

	changed, rev, err := c.Sync(ctx, 4)
	require.NoError(t, err)
	assert.Equal(t, int64(5), rev)
	assert.Equal(t, []secret.Info{wantInfo}, changed)

	got, err := c.Get(ctx, "id1")
	require.NoError(t, err)
	assert.Equal(t, secret.Secret{Info: wantInfo, Data: []byte("data")}, got)

	_, err = c.Get(ctx, "other")
	assert.ErrorIs(t, err, ErrNotFound)

	opts.Token = "expired"
	bad, err := Dial(opts)
	require.NoError(t, err)
	defer bad.Close()

	_, _, err = bad.Sync(ctx, 0)
	assert.ErrorIs(t, err, ErrSessionExpired)
	_, err = bad.Get(ctx, "id1")
	assert.ErrorIs(t, err, ErrSessionExpired)
}

func TestClientWrites(t *testing.T) {
	c, err := Dial(startServer(t, "good"))
	require.NoError(t, err)
	defer c.Close()
	ctx := context.Background()

	info, err := c.Create(ctx, secret.Secret{Info: secret.Info{ID: "new", Type: secret.TypeText, Name: "note"}, Data: []byte("x")})
	require.NoError(t, err)
	assert.Equal(t, "new", info.ID)
	assert.Equal(t, secret.TypeText, info.Type)

	// Stored by an earlier attempt: that's success, not an error.
	info, err = c.Create(ctx, secret.Secret{Info: secret.Info{ID: "stored-before", Name: "note"}})
	require.NoError(t, err)
	assert.Equal(t, "stored-before", info.ID)

	_, err = c.Create(ctx, secret.Secret{})
	assert.EqualError(t, err, "name must be 1-255 characters")

	info, err = c.Update(ctx, secret.Secret{Info: secret.Info{ID: "id1", Name: "renamed", Version: 2}})
	require.NoError(t, err)
	assert.Equal(t, int64(3), info.Version)

	_, err = c.Update(ctx, secret.Secret{Info: secret.Info{ID: "id1", Version: 1}})
	assert.ErrorIs(t, err, ErrConflict)

	assert.NoError(t, c.Delete(ctx, "id1"))
	assert.ErrorIs(t, c.Delete(ctx, "other"), ErrNotFound)
}
