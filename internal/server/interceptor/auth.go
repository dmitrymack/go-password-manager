package interceptor

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TokenVerifier checks a token and returns the user ID inside it.
type TokenVerifier interface {
	Verify(token string) (string, error)
}

// userIDKey is the context key for the authenticated user's ID. An own
// unexported type guarantees no other package can clash with it.
type userIDKey struct{}

// UserID returns the user ID that Auth put into ctx.
func UserID(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(userIDKey{}).(string)
	return id, ok
}

// WithUserID returns a copy of ctx carrying userID. Used by Auth and by
// tests of handlers that need an authenticated context.
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, userIDKey{}, userID)
}

// Auth requires a valid "authorization: Bearer <token>" header on every
// call except methods whose full name starts with one of publicPrefixes.
func Auth(verifier TokenVerifier, publicPrefixes ...string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		for _, prefix := range publicPrefixes {
			if strings.HasPrefix(info.FullMethod, prefix) {
				return handler(ctx, req)
			}
		}

		token := bearerToken(ctx)
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "missing token")
		}

		userID, err := verifier.Verify(token)
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "invalid token")
		}

		return handler(WithUserID(ctx, userID), req)
	}
}

// bearerToken extracts the token from the "authorization" metadata.
func bearerToken(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return ""
	}
	token, found := strings.CutPrefix(values[0], "Bearer ")
	if !found {
		return ""
	}
	return token
}
