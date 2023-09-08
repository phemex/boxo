package namesys

import (
	"context"
	"testing"
	"time"

	"github.com/ipfs/boxo/ipns"
	"github.com/ipfs/boxo/path"
	offroute "github.com/ipfs/boxo/routing/offline"
	ds "github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"
	record "github.com/libp2p/go-libp2p-record"
	ci "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

type mockResolver struct {
	entries map[string]string
}

func testResolution(t *testing.T, resolver Resolver, name string, depth uint, expected string, expectedTTL time.Duration, expectedError error) {
	t.Helper()

	p, ttl, err := resolver.Resolve(context.Background(), name, ResolveWithDepth(depth))
	require.ErrorIs(t, err, expectedError)
	require.Equal(t, expectedTTL, ttl)
	if expected == "" {
		require.Nil(t, p, "%s with depth %d", name, depth)
	} else {
		require.Equal(t, expected, p.String(), "%s with depth %d", name, depth)
	}
}

func (r *mockResolver) resolveOnceAsync(ctx context.Context, name string, options ResolveOptions) <-chan ResolveResult {
	p, err := path.NewPath(r.entries[name])
	out := make(chan ResolveResult, 1)
	out <- ResolveResult{Path: p, Err: err}
	close(out)
	return out
}

func mockResolverOne() *mockResolver {
	return &mockResolver{
		entries: map[string]string{
			"QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy":              "/ipfs/Qmcqtw8FfrVSBaRmbWwHxt3AuySBhJLcvmFYi3Lbc4xnwj",
			"QmbCMUZw6JFeZ7Wp9jkzbye3Fzp2GGcPgC3nmeUjfVF87n":              "/ipns/QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy",
			"QmY3hE8xgFCjGcz6PHgnvJz5HZi1BaKRfPkn1ghZUcYMjD":              "/ipns/ipfs.io",
			"QmQ4QZh8nrsczdUEwTyfBope4THUhqxqc1fx6qYhhzZQei":              "/ipfs/QmP3ouCnU8NNLsW6261pAx2pNLV2E4dQoisB1sgda12Act",
			"12D3KooWFB51PRY9BxcXSH6khFXw1BZeszeLDy7C8GciskqCTZn5":        "/ipns/QmbCMUZw6JFeZ7Wp9jkzbye3Fzp2GGcPgC3nmeUjfVF87n", // ed25519+identity multihash
			"bafzbeickencdqw37dpz3ha36ewrh4undfjt2do52chtcky4rxkj447qhdm": "/ipns/QmbCMUZw6JFeZ7Wp9jkzbye3Fzp2GGcPgC3nmeUjfVF87n", // cidv1 in base32 with libp2p-key multicodec
		},
	}
}

func mockResolverTwo() *mockResolver {
	return &mockResolver{
		entries: map[string]string{
			"ipfs.io": "/ipns/QmbCMUZw6JFeZ7Wp9jkzbye3Fzp2GGcPgC3nmeUjfVF87n",
		},
	}
}

func TestNamesysResolution(t *testing.T) {
	r := &namesys{
		ipnsResolver: mockResolverOne(),
		dnsResolver:  mockResolverTwo(),
	}

	testResolution(t, r, "Qmcqtw8FfrVSBaRmbWwHxt3AuySBhJLcvmFYi3Lbc4xnwj", DefaultDepthLimit, "/ipfs/Qmcqtw8FfrVSBaRmbWwHxt3AuySBhJLcvmFYi3Lbc4xnwj", 0, nil)
	testResolution(t, r, "/ipns/QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy", DefaultDepthLimit, "/ipfs/Qmcqtw8FfrVSBaRmbWwHxt3AuySBhJLcvmFYi3Lbc4xnwj", 0, nil)
	testResolution(t, r, "/ipns/QmbCMUZw6JFeZ7Wp9jkzbye3Fzp2GGcPgC3nmeUjfVF87n", DefaultDepthLimit, "/ipfs/Qmcqtw8FfrVSBaRmbWwHxt3AuySBhJLcvmFYi3Lbc4xnwj", 0, nil)
	testResolution(t, r, "/ipns/QmbCMUZw6JFeZ7Wp9jkzbye3Fzp2GGcPgC3nmeUjfVF87n", 1, "/ipns/QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy", 0, ErrResolveRecursion)
	testResolution(t, r, "/ipns/ipfs.io", DefaultDepthLimit, "/ipfs/Qmcqtw8FfrVSBaRmbWwHxt3AuySBhJLcvmFYi3Lbc4xnwj", 0, nil)
	testResolution(t, r, "/ipns/ipfs.io", 1, "/ipns/QmbCMUZw6JFeZ7Wp9jkzbye3Fzp2GGcPgC3nmeUjfVF87n", 0, ErrResolveRecursion)
	testResolution(t, r, "/ipns/ipfs.io", 2, "/ipns/QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy", 0, ErrResolveRecursion)
	testResolution(t, r, "/ipns/QmY3hE8xgFCjGcz6PHgnvJz5HZi1BaKRfPkn1ghZUcYMjD", DefaultDepthLimit, "/ipfs/Qmcqtw8FfrVSBaRmbWwHxt3AuySBhJLcvmFYi3Lbc4xnwj", 0, nil)
	testResolution(t, r, "/ipns/QmY3hE8xgFCjGcz6PHgnvJz5HZi1BaKRfPkn1ghZUcYMjD", 1, "/ipns/ipfs.io", 0, ErrResolveRecursion)
	testResolution(t, r, "/ipns/QmY3hE8xgFCjGcz6PHgnvJz5HZi1BaKRfPkn1ghZUcYMjD", 2, "/ipns/QmbCMUZw6JFeZ7Wp9jkzbye3Fzp2GGcPgC3nmeUjfVF87n", 0, ErrResolveRecursion)
	testResolution(t, r, "/ipns/QmY3hE8xgFCjGcz6PHgnvJz5HZi1BaKRfPkn1ghZUcYMjD", 3, "/ipns/QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy", 0, ErrResolveRecursion)
	testResolution(t, r, "/ipns/12D3KooWFB51PRY9BxcXSH6khFXw1BZeszeLDy7C8GciskqCTZn5", 1, "/ipns/QmbCMUZw6JFeZ7Wp9jkzbye3Fzp2GGcPgC3nmeUjfVF87n", 0, ErrResolveRecursion)
	testResolution(t, r, "/ipns/bafzbeickencdqw37dpz3ha36ewrh4undfjt2do52chtcky4rxkj447qhdm", 1, "/ipns/QmbCMUZw6JFeZ7Wp9jkzbye3Fzp2GGcPgC3nmeUjfVF87n", 0, ErrResolveRecursion)
}

func TestResolveIPNS(t *testing.T) {
	ns := &namesys{
		ipnsResolver: mockResolverOne(),
		dnsResolver:  mockResolverTwo(),
	}

	inputPath, err := path.NewPath("/ipns/QmatmE9msSfkKxoffpHwNLNKgwZG8eT9Bud6YoPab52vpy/a/b/c")
	require.NoError(t, err)

	res, _, err := Resolve(context.Background(), ns, inputPath)
	require.NoError(t, err)
	require.Equal(t, "/ipfs/Qmcqtw8FfrVSBaRmbWwHxt3AuySBhJLcvmFYi3Lbc4xnwj/a/b/c", res.String())
}

func TestPublishWithCache0(t *testing.T) {
	dst := dssync.MutexWrap(ds.NewMapDatastore())
	priv, _, err := ci.GenerateKeyPair(ci.RSA, 4096)
	require.NoError(t, err)

	routing := offroute.NewOfflineRouter(dst, record.NamespacedValidator{
		"ipns": ipns.Validator{}, // No need for KeyBook, as records created by NameSys include PublicKey for RSA.
		"pk":   record.PublicKeyValidator{},
	})

	nsys, err := NewNameSystem(routing, WithDatastore(dst))
	require.NoError(t, err)

	// CID is arbitrary.
	p, err := path.NewPath("/ipfs/QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn")
	require.NoError(t, err)

	err = nsys.Publish(context.Background(), priv, p)
	require.NoError(t, err)
}

func TestPublishWithTTL(t *testing.T) {
	dst := dssync.MutexWrap(ds.NewMapDatastore())
	priv, _, err := ci.GenerateKeyPair(ci.RSA, 2048)
	require.NoError(t, err)

	pid, err := peer.IDFromPrivateKey(priv)
	require.NoError(t, err)

	routing := offroute.NewOfflineRouter(dst, record.NamespacedValidator{
		"ipns": ipns.Validator{}, // No need for KeyBook, as records created by NameSys include PublicKey for RSA.
		"pk":   record.PublicKeyValidator{},
	})

	ns, err := NewNameSystem(routing, WithDatastore(dst), WithCache(128))
	require.NoError(t, err)

	// CID is arbitrary.
	p, err := path.NewPath("/ipfs/QmUNLLsPACCz1vLxQVkXqqLX5R1X345qqfHbsf67hvA3Nn")
	require.NoError(t, err)

	ttl := 1 * time.Second
	eol := time.Now().Add(2 * time.Second)

	err = ns.Publish(context.Background(), priv, p, PublishWithEOL(eol), PublishWithTTL(ttl))
	require.NoError(t, err)

	entry, ok := ns.(*namesys).cache.Get(ipns.NameFromPeer(pid).String())
	require.True(t, ok)
	require.LessOrEqual(t, entry.eol.Sub(eol), 10*time.Millisecond)
}
