package grpcapi

import (
	"context"
	"errors"

	pb "github.com/dmitrymack/go-password-manager/api/proto"
	"github.com/dmitrymack/go-password-manager/internal/server/interceptor"
	"github.com/dmitrymack/go-password-manager/internal/server/secrets"
	"github.com/dmitrymack/go-password-manager/internal/server/storage"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SecretService is what SecretServer needs from the secrets service.
type SecretService interface {
	Create(ctx context.Context, userID string, in secrets.Input) (storage.Secret, error)
	Update(ctx context.Context, userID, id string, version int64, in secrets.Input) (storage.Secret, error)
	Delete(ctx context.Context, userID, id string) (storage.Secret, error)
	Get(ctx context.Context, userID, id string) (storage.Secret, []byte, error)
	Sync(ctx context.Context, userID string, since int64) ([]storage.Secret, int64, error)
}

// SecretServer implements pb.SecretServiceServer.
type SecretServer struct {
	pb.UnimplementedSecretServiceServer

	svc    SecretService
	logger *zap.Logger
}

// NewSecretServer creates a SecretServer.
func NewSecretServer(svc SecretService, logger *zap.Logger) *SecretServer {
	return &SecretServer{svc: svc, logger: logger}
}

// Create stores a new secret.
func (s *SecretServer) Create(ctx context.Context, req *pb.CreateSecretRequest) (*pb.SecretInfo, error) {
	userID, err := currentUser(ctx)
	if err != nil {
		return nil, err
	}

	secret, err := s.svc.Create(ctx, userID, secrets.Input{
		Type:     int(req.GetType()),
		Name:     req.GetName(),
		Metadata: req.GetMetadata(),
		Data:     req.GetData(),
	})
	if err != nil {
		return nil, s.secretError(err)
	}
	return toInfo(secret), nil
}

// Update replaces a secret's content.
func (s *SecretServer) Update(ctx context.Context, req *pb.UpdateSecretRequest) (*pb.SecretInfo, error) {
	userID, err := currentUser(ctx)
	if err != nil {
		return nil, err
	}

	secret, err := s.svc.Update(ctx, userID, req.GetId(), req.GetVersion(), secrets.Input{
		Name:     req.GetName(),
		Metadata: req.GetMetadata(),
		Data:     req.GetData(),
	})
	if err != nil {
		return nil, s.secretError(err)
	}
	return toInfo(secret), nil
}

// Delete deletes a secret.
func (s *SecretServer) Delete(ctx context.Context, req *pb.DeleteSecretRequest) (*pb.SecretInfo, error) {
	userID, err := currentUser(ctx)
	if err != nil {
		return nil, err
	}

	secret, err := s.svc.Delete(ctx, userID, req.GetId())
	if err != nil {
		return nil, s.secretError(err)
	}
	return toInfo(secret), nil
}

// Get returns a secret with its data.
func (s *SecretServer) Get(ctx context.Context, req *pb.GetSecretRequest) (*pb.Secret, error) {
	userID, err := currentUser(ctx)
	if err != nil {
		return nil, err
	}

	secret, data, err := s.svc.Get(ctx, userID, req.GetId())
	if err != nil {
		return nil, s.secretError(err)
	}
	return &pb.Secret{Info: toInfo(secret), Data: data}, nil
}

// Sync returns secrets changed since the client's revision.
func (s *SecretServer) Sync(ctx context.Context, req *pb.SyncRequest) (*pb.SyncResponse, error) {
	userID, err := currentUser(ctx)
	if err != nil {
		return nil, err
	}

	changed, revision, err := s.svc.Sync(ctx, userID, req.GetSinceRevision())
	if err != nil {
		return nil, s.secretError(err)
	}

	resp := &pb.SyncResponse{Revision: revision}
	for _, secret := range changed {
		resp.Changed = append(resp.Changed, toInfo(secret))
	}
	return resp, nil
}

// currentUser returns the user ID put into ctx by the auth interceptor.
func currentUser(ctx context.Context) (string, error) {
	userID, ok := interceptor.UserID(ctx)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "not authenticated")
	}
	return userID, nil
}

// toInfo converts a stored secret to its API form, without data.
func toInfo(s storage.Secret) *pb.SecretInfo {
	return &pb.SecretInfo{
		Id:            s.ID,
		Type:          pb.SecretType(s.Type), //nolint:gosec // types are 1-4
		Name:          s.Name,
		Metadata:      s.Metadata,
		Version:       s.Version,
		Revision:      s.Revision,
		Deleted:       s.Deleted,
		UpdatedAtUnix: s.UpdatedAt.Unix(),
	}
}

// secretError maps a secrets service error to a gRPC status.
func (s *SecretServer) secretError(err error) error {
	switch {
	case errors.Is(err, secrets.ErrBadType),
		errors.Is(err, secrets.ErrBadName),
		errors.Is(err, secrets.ErrDataTooLarge),
		errors.Is(err, secrets.ErrTooMuchMetadata):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, secrets.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, secrets.ErrVersionConflict):
		return status.Error(codes.Aborted, err.Error())
	default:
		s.logger.Error("secret operation failed", zap.Error(err))
		return status.Error(codes.Internal, "internal error")
	}
}
