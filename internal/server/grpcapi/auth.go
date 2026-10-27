// Package grpcapi adapts the services to the gRPC API: it unpacks
// requests, calls a service and turns its errors into gRPC status codes.
package grpcapi

import (
	"context"
	"errors"

	pb "github.com/dmitrymack/go-password-manager/api/proto"
	"github.com/dmitrymack/go-password-manager/internal/server/auth"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthService is what AuthServer needs from the auth service.
type AuthService interface {
	Register(ctx context.Context, login, password string) (string, error)
	Login(ctx context.Context, login, password string) (string, error)
}

// AuthServer implements pb.AuthServiceServer.
type AuthServer struct {
	pb.UnimplementedAuthServiceServer

	svc    AuthService
	logger *zap.Logger
}

// NewAuthServer creates an AuthServer.
func NewAuthServer(svc AuthService, logger *zap.Logger) *AuthServer {
	return &AuthServer{svc: svc, logger: logger}
}

// Register creates a user and returns their token.
func (s *AuthServer) Register(ctx context.Context, req *pb.Credentials) (*pb.AuthResponse, error) {
	token, err := s.svc.Register(ctx, req.GetLogin(), req.GetPassword())
	if err != nil {
		return nil, s.authError(err)
	}
	return &pb.AuthResponse{Token: token}, nil
}

// Login authenticates a user and returns their token.
func (s *AuthServer) Login(ctx context.Context, req *pb.Credentials) (*pb.AuthResponse, error) {
	token, err := s.svc.Login(ctx, req.GetLogin(), req.GetPassword())
	if err != nil {
		return nil, s.authError(err)
	}
	return &pb.AuthResponse{Token: token}, nil
}

// authError maps an auth service error to a gRPC status. Unknown errors
// are logged and hidden from the client.
func (s *AuthServer) authError(err error) error {
	switch {
	case errors.Is(err, auth.ErrBadLogin),
		errors.Is(err, auth.ErrPasswordLength),
		errors.Is(err, auth.ErrPasswordTooWeak):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, auth.ErrLoginTaken):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, auth.ErrInvalidCredentials):
		return status.Error(codes.Unauthenticated, err.Error())
	default:
		s.logger.Error("auth failed", zap.Error(err))
		return status.Error(codes.Internal, "internal error")
	}
}
