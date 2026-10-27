package cli

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	"github.com/dmitrymack/go-password-manager/internal/client/api"
	"github.com/dmitrymack/go-password-manager/internal/client/cache"
	"github.com/dmitrymack/go-password-manager/internal/client/payload"
	"github.com/dmitrymack/go-password-manager/internal/client/secret"
	"github.com/dmitrymack/go-password-manager/internal/client/syncer"
	"github.com/spf13/cobra"
)

// maxDataSize is the server's limit on a secret's data.
const maxDataSize = 10 << 20

var errReadOnly = errors.New("server unavailable: read-only mode, changes are not possible")

// typeFlags are the content flags that apply to each secret type.
var typeFlags = map[secret.Type][]string{
	secret.TypeLogin:  {"login", "password"},
	secret.TypeCard:   {"number", "holder", "expiry", "cvv"},
	secret.TypeText:   {"text", "file"},
	secret.TypeBinary: {"file"},
}

// contentFlagNames are all type-specific flags of edit.
var contentFlagNames = []string{"login", "password", "number", "holder", "expiry", "cvv", "text", "file"}

// contentFlags are the flags that set a secret's content.
type contentFlags struct {
	name     string   // edit: new name
	meta     []string // key=value; an empty value removes the key
	login    string
	password bool // edit: ask for a new password
	number   string
	holder   string
	expiry   string
	cvv      bool // edit: ask for a new CVV
	text     string
	file     string
}

func (a *app) newAddCmd() *cobra.Command {
	add := &cobra.Command{
		Use:   "add",
		Short: "Add a secret: login, card, text or binary",
	}
	for _, t := range []secret.Type{secret.TypeLogin, secret.TypeCard, secret.TypeText, secret.TypeBinary} {
		add.AddCommand(a.newAddTypeCmd(t))
	}
	return add
}

func (a *app) newAddTypeCmd(t secret.Type) *cobra.Command {
	f := &contentFlags{}
	cmd := &cobra.Command{
		Use:   t.String() + " <name>",
		Short: "Add a " + t.String() + " secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := a.buildData(t, nil, f)
			if err != nil {
				return err
			}
			meta, err := applyMeta(nil, f.meta)
			if err != nil {
				return err
			}

			s := secret.Secret{Info: secret.Info{Type: t, Name: args[0], Metadata: meta}, Data: data}
			return a.write(cmd, func(ctx context.Context, client API, _ *cache.Cache) (string, error) {
				_, err := client.Create(ctx, s)
				return "Added " + s.Name, err
			})
		},
	}

	flags := cmd.Flags()
	flags.StringArrayVar(&f.meta, "meta", nil, "metadata key=value (repeatable)")
	switch t {
	case secret.TypeLogin:
		flags.StringVar(&f.login, "login", "", "login (required); the password is asked for")
	case secret.TypeCard:
		flags.StringVar(&f.number, "number", "", "card number (required); the CVV is asked for")
		flags.StringVar(&f.holder, "holder", "", "card holder")
		flags.StringVar(&f.expiry, "expiry", "", "expiry date MM/YY (required)")
	case secret.TypeText:
		flags.StringVar(&f.text, "text", "", "the text")
		flags.StringVar(&f.file, "file", "", "read the text from a file")
	case secret.TypeBinary:
		flags.StringVar(&f.file, "file", "", "file to store (required)")
	}
	return cmd
}

func (a *app) newEditCmd() *cobra.Command {
	f := &contentFlags{}
	cmd := &cobra.Command{
		Use:   "edit <name or id>",
		Short: "Change a secret; only the given fields change",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.write(cmd, func(ctx context.Context, client API, c *cache.Cache) (string, error) {
				s, err := c.Get(ctx, args[0])
				if err != nil {
					return "", err
				}
				if err := checkFlagsApply(cmd, s.Type); err != nil {
					return "", err
				}

				if s.Data, err = a.buildData(s.Type, s.Data, f); err != nil {
					return "", err
				}
				if s.Metadata, err = applyMeta(s.Metadata, f.meta); err != nil {
					return "", err
				}
				if f.name != "" {
					s.Name = f.name
				}

				_, err = client.Update(ctx, s)
				return "Updated " + s.Name, err
			})
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&f.name, "name", "", "new name")
	flags.StringArrayVar(&f.meta, "meta", nil, "set metadata key=value; key= removes it (repeatable)")
	flags.StringVar(&f.login, "login", "", "login: new login")
	flags.BoolVar(&f.password, "password", false, "login: ask for a new password")
	flags.StringVar(&f.number, "number", "", "card: new number")
	flags.StringVar(&f.holder, "holder", "", "card: new holder")
	flags.StringVar(&f.expiry, "expiry", "", "card: new expiry MM/YY")
	flags.BoolVar(&f.cvv, "cvv", false, "card: ask for a new CVV")
	flags.StringVar(&f.text, "text", "", "text: new text")
	flags.StringVar(&f.file, "file", "", "text/binary: new content from a file")
	return cmd
}

func (a *app) newDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <name or id>",
		Short: "Delete a secret",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return a.write(cmd, func(ctx context.Context, client API, c *cache.Cache) (string, error) {
				s, err := c.Get(ctx, args[0])
				if err != nil {
					return "", err
				}
				return "Deleted " + s.Name, client.Delete(ctx, s.ID)
			})
		},
	}
}

// write syncs, runs change on the server, syncs again and prints change's
// message. Without the server it fails: offline mode is read-only.
func (a *app) write(cmd *cobra.Command, change func(ctx context.Context, client API, c *cache.Cache) (string, error)) error {
	sess, c, err := a.openCache()
	if err != nil {
		return err
	}
	defer c.Close() //nolint:errcheck // nothing to do on failure

	var msg string
	err = a.withServer(cmd.Context(), sess, func(ctx context.Context, client API) error {
		// Sync first: edit and delete need the latest versions.
		if _, err := syncer.Run(ctx, client, c); err != nil {
			return err
		}
		if msg, err = change(ctx, client, c); err != nil {
			return err
		}
		_, err := syncer.Run(ctx, client, c)
		return err
	})
	if errors.Is(err, api.ErrUnavailable) {
		return errReadOnly
	}
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(cmd.OutOrStdout(), msg)
	return err
}

// buildData returns the new data of a secret of type t. old is the
// current data when editing, nil when adding.
func (a *app) buildData(t secret.Type, old []byte, f *contentFlags) ([]byte, error) {
	editing := old != nil

	switch t {
	case secret.TypeLogin:
		var l payload.Login
		if editing {
			var err error
			if l, err = payload.DecodeLogin(old); err != nil {
				return nil, err
			}
		}
		if f.login != "" {
			l.Login = f.login
		}
		if l.Login == "" {
			return nil, errors.New("--login is required")
		}
		if !editing || f.password {
			password, err := a.readRequired("Password: ")
			if err != nil {
				return nil, err
			}
			l.Password = password
		}
		return payload.Encode(l)

	case secret.TypeCard:
		var c payload.Card
		if editing {
			var err error
			if c, err = payload.DecodeCard(old); err != nil {
				return nil, err
			}
		}
		c.Number = cmp.Or(f.number, c.Number) // first non-empty
		c.Holder = cmp.Or(f.holder, c.Holder)
		c.Expiry = cmp.Or(f.expiry, c.Expiry)
		if !editing || f.cvv {
			cvv, err := a.readRequired("CVV: ")
			if err != nil {
				return nil, err
			}
			c.CVV = cvv
		}
		if err := c.Validate(); err != nil {
			return nil, err
		}
		return payload.Encode(c)

	case secret.TypeText:
		switch {
		case f.text != "":
			return []byte(f.text), nil
		case f.file != "":
			return readFile(f.file)
		case editing:
			return old, nil
		}
		return nil, errors.New("--text or --file is required")

	default: // binary
		if f.file != "" {
			return readFile(f.file)
		}
		if editing {
			return old, nil
		}
		return nil, errors.New("--file is required")
	}
}

// readRequired asks for a hidden value that must not be empty.
func (a *app) readRequired(prompt string) (string, error) {
	v, err := a.deps.ReadPassword(prompt)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", fmt.Errorf("%s must not be empty", strings.TrimSuffix(prompt, ": "))
	}
	return v, nil
}

// readFile reads a file to store, refusing ones over the size limit.
func readFile(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxDataSize {
		return nil, fmt.Errorf("%s is larger than 10 MB", path)
	}
	return os.ReadFile(path) //nolint:gosec // the user chooses which file to store
}

// applyMeta returns a copy of old with the key=value pairs applied.
func applyMeta(old map[string]string, pairs []string) (map[string]string, error) {
	meta := maps.Clone(old)
	if meta == nil {
		meta = map[string]string{}
	}

	for _, pair := range pairs {
		key, value, ok := strings.Cut(pair, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("--meta %q: want key=value", pair)
		}
		if value == "" {
			delete(meta, key)
		} else {
			meta[key] = value
		}
	}
	return meta, nil
}

// checkFlagsApply rejects edit flags meant for another secret type.
func checkFlagsApply(cmd *cobra.Command, t secret.Type) error {
	var wrong []string
	for _, name := range contentFlagNames {
		if cmd.Flags().Changed(name) && !slices.Contains(typeFlags[t], name) {
			wrong = append(wrong, "--"+name)
		}
	}
	if len(wrong) > 0 {
		return fmt.Errorf("%s: not applicable to a %s secret", strings.Join(wrong, ", "), t)
	}
	return nil
}
