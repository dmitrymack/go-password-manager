package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/dmitrymack/go-password-manager/internal/client/api"
	"github.com/dmitrymack/go-password-manager/internal/client/cache"
	"github.com/dmitrymack/go-password-manager/internal/client/secret"
	"github.com/dmitrymack/go-password-manager/internal/client/session"
	"github.com/dmitrymack/go-password-manager/internal/client/syncer"
	"github.com/spf13/cobra"
)

const (
	cacheFileName = "cache.db"
	syncTimeout   = 2 * time.Minute // a sync may download several large secrets
)

func (a *app) newSyncCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "sync",
		Short: "Download changes from the server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sess, c, err := a.openCache()
			if err != nil {
				return err
			}
			defer c.Close() //nolint:errcheck // read-mostly; nothing to do on failure

			res, err := a.sync(cmd.Context(), sess, c)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Synced: %d updated, %d deleted\n", res.Updated, res.Deleted)
			return err
		},
	}
}

func (a *app) newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List secrets (works offline from the local cache)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sess, c, err := a.openCache()
			if err != nil {
				return err
			}
			defer c.Close() //nolint:errcheck // read-mostly; nothing to do on failure

			if err := a.syncOrWarn(cmd, sess, c); err != nil {
				return err
			}

			list, err := c.List(cmd.Context())
			if err != nil {
				return err
			}
			return printList(cmd.OutOrStdout(), list)
		},
	}
}

func (a *app) newGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get <name or id>",
		Short: "Show a secret (works offline from the local cache)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, c, err := a.openCache()
			if err != nil {
				return err
			}
			defer c.Close() //nolint:errcheck // read-mostly; nothing to do on failure

			if err := a.syncOrWarn(cmd, sess, c); err != nil {
				return err
			}

			s, err := c.Get(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return printSecret(cmd.OutOrStdout(), s)
		},
	}
}

// openCache loads the session and opens its local cache.
func (a *app) openCache() (session.Session, *cache.Cache, error) {
	sess, err := session.Load(a.dataDir)
	if err != nil {
		return session.Session{}, nil, err
	}
	c, err := cache.Open(filepath.Join(a.dataDir, cacheFileName), sess.CacheKey)
	if err != nil {
		return session.Session{}, nil, err
	}
	return sess, c, nil
}

// sync downloads changes from the server into the cache.
func (a *app) sync(ctx context.Context, sess session.Session, c *cache.Cache) (syncer.Result, error) {
	opts := a.conn
	opts.Token = sess.Token
	client, err := a.deps.Connect(opts)
	if err != nil {
		return syncer.Result{}, err
	}
	defer client.Close() //nolint:errcheck // nothing useful to do if closing fails

	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()

	return syncer.Run(ctx, client, c)
}

// syncOrWarn syncs, but if the server is unreachable only prints a
// warning: the command then works read-only from the cache.
func (a *app) syncOrWarn(cmd *cobra.Command, sess session.Session, c *cache.Cache) error {
	_, err := a.sync(cmd.Context(), sess, c)
	if errors.Is(err, api.ErrUnavailable) {
		_, err = fmt.Fprintln(cmd.ErrOrStderr(), "Warning: server unavailable, showing cached data (read-only mode)")
	}
	return err
}

// removeCache deletes the local cache file, if any.
func (a *app) removeCache() error {
	err := os.Remove(filepath.Join(a.dataDir, cacheFileName))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("removing cache: %w", err)
	}
	return nil
}

// printList prints secrets as an aligned table.
func printList(w io.Writer, list []secret.Info) error {
	if len(list) == 0 {
		_, err := fmt.Fprintln(w, "No secrets yet")
		return err
	}

	// tabwriter buffers: write errors surface in Flush.
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "NAME\tTYPE\tMETADATA\tUPDATED\tID")
	for _, s := range list {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			s.Name, s.Type, formatMetadata(s.Metadata), s.UpdatedAt.Format(time.DateTime), s.ID)
	}
	return tw.Flush()
}

// printSecret prints one secret with its data.
func printSecret(w io.Writer, s secret.Secret) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintf(tw, "Name:\t%s\n", s.Name)
	_, _ = fmt.Fprintf(tw, "Type:\t%s\n", s.Type)
	_, _ = fmt.Fprintf(tw, "ID:\t%s\n", s.ID)
	_, _ = fmt.Fprintf(tw, "Updated:\t%s\n", s.UpdatedAt.Format(time.DateTime))
	if len(s.Metadata) > 0 {
		_, _ = fmt.Fprintf(tw, "Metadata:\t%s\n", formatMetadata(s.Metadata))
	}
	if s.Type == secret.TypeBinary {
		_, _ = fmt.Fprintf(tw, "Data:\t<%d bytes of binary data>\n", len(s.Data))
	} else {
		_, _ = fmt.Fprintf(tw, "Data:\t%s\n", s.Data)
	}
	return tw.Flush()
}

// formatMetadata renders metadata as "k1=v1, k2=v2", sorted by key.
func formatMetadata(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, k+"="+m[k])
	}
	return strings.Join(pairs, ", ")
}
