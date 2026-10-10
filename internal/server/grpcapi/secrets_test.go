package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/dmitrymack/go-password-manager/api/proto"
	"github.com/dmitrymack/go-password-manager/internal/server/interceptor"
	"github.com/dmitrymack/go-password-manager/internal/server/secrets"
	"github.com/dmitrymack/go-password-manager/internal/server/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeSecrets records the last input and returns a fixed secret or err.
type fakeSecrets struct {
	err       error
	gotUserID string
	gotInput  secrets.Input
}

var testSecret = storage.Secret{
	ID: "id1", Type: secrets.TypeLogin, Name: "github", Metadata: map[string]string{"k": "v"},
	Version: 2, Revision: 5, UpdatedAt: time.Unix(1700000000, 0),
}

func (f *fakeSecrets) Create(_ context.Context, userID string, in secrets.Input) (storage.Secret, error) {
	f.gotUserID, f.gotInput = userID, in
	return testSecret, f.err
}

func (f *fakeSecrets) Update(_ context.Context, userID, _ string, _ int64, in secrets.Input) (storage.Secret, error) {
	f.gotUserID, f.gotInput = userID, in
	return testSecret, f.err
}

func (f *fakeSecrets) Delete(_ context.Context, userID, _ string) (storage.Secret, error) {
	f.gotUserID = userID
	return testSecret, f.err
}

func (f *fakeSecrets) Get(_ context.Context, userID, _ string) (storage.Secret, []byte, error) {
	f.gotUserID = userID
	return testSecret, []byte("data"), f.err
}

func (f *fakeSecrets) Sync(_ context.Context, userID string, _ int64) ([]storage.Secret, int64, error) {
	f.gotUserID = userID
	return []storage.Secret{testSecret}, 5, f.err
}

var wantInfo = &pb.SecretInfo{
	Id: "id1", Type: pb.SecretType_SECRET_TYPE_LOGIN, Name: "github", Metadata: map[string]string{"k": "v"},
	Version: 2, Revision: 5, UpdatedAtUnix: 1700000000,
}

func TestSecretServerCalls(t *testing.T) {
	fake := &fakeSecrets{}
	srv := NewSecretServer(fake, zap.NewNop())
	ctx := interceptor.WithUserID(context.Background(), "alice")

	info, err := srv.Create(ctx, &pb.CreateSecretRequest{
		Type: pb.SecretType_SECRET_TYPE_CARD, Name: "visa", Metadata: map[string]string{"bank": "x"}, Data: []byte("d"),
	})
	require.NoError(t, err)
	assert.Equal(t, wantInfo, info)
	assert.Equal(t, "alice", fake.gotUserID)
	assert.Equal(t, secrets.Input{Type: secrets.TypeCard, Name: "visa", Metadata: map[string]string{"bank": "x"}, Data: []byte("d")}, fake.gotInput)

	info, err = srv.Update(ctx, &pb.UpdateSecretRequest{Id: "id1", Version: 1, Name: "visa2"})
	require.NoError(t, err)
	assert.Equal(t, wantInfo, info)
	assert.Equal(t, "visa2", fake.gotInput.Name)

	info, err = srv.Delete(ctx, &pb.DeleteSecretRequest{Id: "id1"})
	require.NoError(t, err)
	assert.Equal(t, wantInfo, info)

	secret, err := srv.Get(ctx, &pb.GetSecretRequest{Id: "id1"})
	require.NoError(t, err)
	assert.Equal(t, wantInfo, secret.GetInfo())
	assert.Equal(t, []byte("data"), secret.GetData())

	resp, err := srv.Sync(ctx, &pb.SyncRequest{SinceRevision: 0})
	require.NoError(t, err)
	assert.Equal(t, int64(5), resp.GetRevision())
	assert.Equal(t, []*pb.SecretInfo{wantInfo}, resp.GetChanged())
}

func TestSecretServerErrors(t *testing.T) {
	tests := []struct {
		err  error
		want codes.Code
	}{
		{secrets.ErrBadType, codes.InvalidArgument},
		{secrets.ErrBadName, codes.InvalidArgument},
		{secrets.ErrDataTooLarge, codes.InvalidArgument},
		{secrets.ErrTooMuchMetadata, codes.InvalidArgument},
		{secrets.ErrNotFound, codes.NotFound},
		{secrets.ErrVersionConflict, codes.Aborted},
		{errors.New("db is down"), codes.Internal},
	}

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			srv := NewSecretServer(&fakeSecrets{err: tt.err}, zap.NewNop())
			ctx := interceptor.WithUserID(context.Background(), "alice")

			_, err := srv.Create(ctx, &pb.CreateSecretRequest{})
			assert.Equal(t, tt.want, status.Code(err), "Create")
			_, err = srv.Update(ctx, &pb.UpdateSecretRequest{})
			assert.Equal(t, tt.want, status.Code(err), "Update")
			_, err = srv.Delete(ctx, &pb.DeleteSecretRequest{})
			assert.Equal(t, tt.want, status.Code(err), "Delete")
			_, err = srv.Get(ctx, &pb.GetSecretRequest{})
			assert.Equal(t, tt.want, status.Code(err), "Get")
			_, err = srv.Sync(ctx, &pb.SyncRequest{})
			assert.Equal(t, tt.want, status.Code(err), "Sync")
		})
	}
}

func TestSecretServerNeedsUser(t *testing.T) {
	srv := NewSecretServer(&fakeSecrets{}, zap.NewNop())
	ctx := context.Background() // no user: the interceptor didn't run

	_, err := srv.Create(ctx, &pb.CreateSecretRequest{})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = srv.Update(ctx, &pb.UpdateSecretRequest{})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = srv.Delete(ctx, &pb.DeleteSecretRequest{})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = srv.Get(ctx, &pb.GetSecretRequest{})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = srv.Sync(ctx, &pb.SyncRequest{})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
