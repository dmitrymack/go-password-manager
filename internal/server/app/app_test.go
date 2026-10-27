package app

import (
	"context"
	"net"
	"testing"
	"time"

	pb "github.com/dmitrymack/go-password-manager/api/proto"
	"github.com/dmitrymack/go-password-manager/internal/server/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// fakeAuth registers anyone and issues the token "tok".
type fakeAuth struct{}

func (fakeAuth) Register(context.Context, string, string) (string, error) { return "tok", nil }
func (fakeAuth) Login(context.Context, string, string) (string, error)    { return "tok", nil }

// rejectAll is a TokenVerifier that accepts no token.
type rejectAll struct{}

func (rejectAll) Verify(string) (string, error) { return "", assert.AnError }

var testServices = Services{Auth: fakeAuth{}, Tokens: rejectAll{}}

func TestServeAndShutdown(t *testing.T) {
	a, err := New(&config.Config{GRPCAddress: "unused"}, zap.NewNop(), testServices)
	require.NoError(t, err)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Serve(ctx, lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	resp, err := healthpb.NewHealthClient(conn).Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())

	// Auth methods are public: they work without a token.
	authResp, err := pb.NewAuthServiceClient(conn).Register(context.Background(), &pb.Credentials{})
	require.NoError(t, err)
	assert.Equal(t, "tok", authResp.GetToken())

	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down")
	}
}

func TestNewTLSErrors(t *testing.T) {
	_, err := New(&config.Config{TLSCertFile: "missing.pem", TLSKeyFile: "missing.key"}, zap.NewNop(), testServices)
	assert.Error(t, err)
}

func TestRunListenError(t *testing.T) {
	a, err := New(&config.Config{GRPCAddress: "bad address"}, zap.NewNop(), testServices)
	require.NoError(t, err)
	assert.Error(t, a.Run(context.Background()))
}
