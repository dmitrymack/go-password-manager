package interceptor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// fakeVerifier accepts only the token "good", for user "u1".
type fakeVerifier struct{}

func (fakeVerifier) Verify(token string) (string, error) {
	if token == "good" {
		return "u1", nil
	}
	return "", errors.New("bad token")
}

func TestAuth(t *testing.T) {
	intercept := Auth(fakeVerifier{}, "/public.Service/")

	tests := []struct {
		name       string
		method     string
		authHeader string // empty means no header
		wantCode   codes.Code
		wantUserID string
	}{
		{name: "public method", method: "/public.Service/Login", wantCode: codes.OK},
		{name: "valid token", method: "/private.Service/Get", authHeader: "Bearer good", wantCode: codes.OK, wantUserID: "u1"},
		{name: "no header", method: "/private.Service/Get", wantCode: codes.Unauthenticated},
		{name: "no Bearer prefix", method: "/private.Service/Get", authHeader: "good", wantCode: codes.Unauthenticated},
		{name: "invalid token", method: "/private.Service/Get", authHeader: "Bearer bad", wantCode: codes.Unauthenticated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.authHeader != "" {
				ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("authorization", tt.authHeader))
			}

			var gotUserID string
			handler := func(ctx context.Context, _ any) (any, error) {
				gotUserID, _ = UserID(ctx)
				return "resp", nil
			}

			_, err := intercept(ctx, nil, &grpc.UnaryServerInfo{FullMethod: tt.method}, handler)
			require.Equal(t, tt.wantCode, status.Code(err))
			assert.Equal(t, tt.wantUserID, gotUserID)
		})
	}
}
