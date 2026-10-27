package interceptor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLogging(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{name: "ok", wantCode: "OK"},
		{name: "error", err: status.Error(codes.NotFound, "nope"), wantCode: "NotFound"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.InfoLevel)
			intercept := Logging(zap.New(core))

			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
			handler := func(context.Context, any) (any, error) { return "resp", tt.err }

			resp, err := intercept(context.Background(), "req", info, handler)
			assert.Equal(t, "resp", resp)
			assert.Equal(t, tt.err, err)

			require.Equal(t, 1, logs.Len())
			fields := logs.All()[0].ContextMap()
			assert.Equal(t, "/test.Service/Method", fields["method"])
			assert.Equal(t, tt.wantCode, fields["code"])
		})
	}
}
