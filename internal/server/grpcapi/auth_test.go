package grpcapi

import (
	"context"
	"errors"
	"testing"

	pb "github.com/dmitrymack/go-password-manager/api/proto"
	"github.com/dmitrymack/go-password-manager/internal/server/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeAuth returns the configured token and error from both methods.
type fakeAuth struct {
	token string
	err   error
}

func (f fakeAuth) Register(context.Context, string, string) (string, error) { return f.token, f.err }
func (f fakeAuth) Login(context.Context, string, string) (string, error)    { return f.token, f.err }

func TestAuthServer(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode codes.Code
	}{
		{name: "ok", wantCode: codes.OK},
		{name: "bad login", err: auth.ErrBadLogin, wantCode: codes.InvalidArgument},
		{name: "short password", err: auth.ErrPasswordLength, wantCode: codes.InvalidArgument},
		{name: "weak password", err: auth.ErrPasswordTooWeak, wantCode: codes.InvalidArgument},
		{name: "taken", err: auth.ErrLoginTaken, wantCode: codes.AlreadyExists},
		{name: "wrong password", err: auth.ErrInvalidCredentials, wantCode: codes.Unauthenticated},
		{name: "internal", err: errors.New("db is down"), wantCode: codes.Internal},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := NewAuthServer(fakeAuth{token: "tok", err: tt.err}, zap.NewNop())
			req := &pb.Credentials{Login: "alice", Password: "passw0rd"}

			for _, call := range []func(context.Context, *pb.Credentials) (*pb.AuthResponse, error){
				srv.Register, srv.Login,
			} {
				resp, err := call(context.Background(), req)
				require.Equal(t, tt.wantCode, status.Code(err))
				if tt.wantCode == codes.OK {
					assert.Equal(t, "tok", resp.GetToken())
				}
			}
		})
	}
}
