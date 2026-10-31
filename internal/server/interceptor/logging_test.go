package interceptor

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLogging(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantCode  string
		wantLevel zapcore.Level
	}{
		{name: "ok", wantCode: "OK", wantLevel: zap.InfoLevel},
		{name: "client error", err: status.Error(codes.NotFound, "nope"), wantCode: "NotFound", wantLevel: zap.DebugLevel},
		{name: "server error", err: status.Error(codes.Internal, "boom"), wantCode: "Internal", wantLevel: zap.ErrorLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, logs := observer.New(zap.DebugLevel)
			intercept := Logging(zap.New(core))

			info := &grpc.UnaryServerInfo{FullMethod: "/test.Service/Method"}
			handler := func(context.Context, any) (any, error) { return "resp", tt.err }

			resp, err := intercept(context.Background(), "req", info, handler)
			assert.Equal(t, "resp", resp)
			assert.Equal(t, tt.err, err)

			require.Equal(t, 1, logs.Len())
			entry := logs.All()[0]
			assert.Equal(t, tt.wantLevel, entry.Level)
			fields := entry.ContextMap()
			assert.Equal(t, "/test.Service/Method", fields["method"])
			assert.Equal(t, tt.wantCode, fields["code"])
		})
	}
}
