// Package interceptor contains gRPC server interceptors.
package interceptor

import (
	"context"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Logging logs each call's method, status code and duration: successful
// calls at Info, server errors at Error, client errors (like HTTP 4xx) at
// Debug. Request bodies are not logged: they contain secrets.
func Logging(logger *zap.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)

		code := status.Code(err)
		fields := []zap.Field{
			zap.String("method", info.FullMethod),
			zap.String("code", code.String()),
			zap.Duration("duration", time.Since(start)),
		}

		switch code {
		case codes.OK:
			logger.Info("gRPC call", fields...)
		case codes.Unknown, codes.Internal, codes.DataLoss:
			logger.Error("gRPC call failed", append(fields, zap.Error(err))...)
		default:
			logger.Debug("gRPC call rejected", fields...)
		}

		return resp, err
	}
}
