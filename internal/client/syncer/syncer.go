// Package syncer brings the local cache up to date with the server.
package syncer

import (
	"context"
	"errors"
	"fmt"

	"github.com/dmitrymack/go-password-manager/internal/client/api"
	"github.com/dmitrymack/go-password-manager/internal/client/secret"
)

// Remote is the server side of a sync.
type Remote interface {
	Sync(ctx context.Context, since int64) ([]secret.Info, int64, error)
	Get(ctx context.Context, id string) (secret.Secret, error)
}

// Local is the cache side of a sync.
type Local interface {
	Revision(ctx context.Context) (int64, error)
	SetRevision(ctx context.Context, rev int64) error
	Put(ctx context.Context, s secret.Secret) error
	Delete(ctx context.Context, id string) error
}

// Result counts what a sync changed locally.
type Result struct {
	Updated int
	Deleted int
}

// Run fetches changes since the cache's revision and applies them.
// The revision is saved last: if anything fails, the next run redoes it.
func Run(ctx context.Context, remote Remote, local Local) (Result, error) {
	var res Result

	since, err := local.Revision(ctx)
	if err != nil {
		return res, fmt.Errorf("reading local revision: %w", err)
	}

	changed, rev, err := remote.Sync(ctx, since)
	if err != nil {
		return res, err
	}

	for _, info := range changed {
		if info.Deleted {
			if err := local.Delete(ctx, info.ID); err != nil {
				return res, err
			}
			res.Deleted++
			continue
		}

		s, err := remote.Get(ctx, info.ID)
		if errors.Is(err, api.ErrNotFound) {
			continue // deleted after Sync; the deletion comes next time
		}
		if err != nil {
			return res, err
		}

		if err := local.Put(ctx, s); err != nil {
			return res, err
		}
		res.Updated++
	}

	if err := local.SetRevision(ctx, rev); err != nil {
		return res, fmt.Errorf("saving local revision: %w", err)
	}
	return res, nil
}
