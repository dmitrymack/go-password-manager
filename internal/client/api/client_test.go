package api

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/dmitrymack/go-password-manager/api/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeAuthServer accepts only the password "right".
type fakeAuthServer struct {
	pb.UnimplementedAuthServiceServer
}

func (fakeAuthServer) Register(_ context.Context, req *pb.Credentials) (*pb.AuthResponse, error) {
	return &pb.AuthResponse{Token: "reg-" + req.GetLogin()}, nil
}

func (fakeAuthServer) Login(_ context.Context, req *pb.Credentials) (*pb.AuthResponse, error) {
	if req.GetPassword() != "right" {
		return nil, status.Error(codes.Unauthenticated, "invalid login or password")
	}
	return &pb.AuthResponse{Token: "login-" + req.GetLogin()}, nil
}

// startServer runs fakeAuthServer on a free port and returns its address.
func startServer(t *testing.T) string {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	srv := grpc.NewServer()
	pb.RegisterAuthServiceServer(srv, fakeAuthServer{})
	go srv.Serve(lis) //nolint:errcheck // returns when the test stops the server
	t.Cleanup(srv.Stop)

	return lis.Addr().String()
}

func TestClientAuth(t *testing.T) {
	c, err := Dial(Options{Address: startServer(t), Plaintext: true})
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

	c, err := Dial(Options{Address: addr, Plaintext: true})
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
