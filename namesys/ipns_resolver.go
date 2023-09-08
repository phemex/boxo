package namesys

import (
	"context"
	"time"

	"github.com/ipfs/boxo/ipns"
	"github.com/ipfs/boxo/path"

	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/routing"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// IPNSResolver implements [Resolver] for IPNS Records. This resolver always returns
// a TTL if the record is still valid. It happens as follows:
//
//  1. Provisory TTL is chosen: record TTL if it exists, otherwise [DefaultIPNSRecordTTL].
//  2. If provisory TTL expires before EOL, then returned TTL is duration between EOL and now.
//  3. If record is expired, 0 is returned as TTL.
type IPNSResolver struct {
	routing routing.ValueStore
}

var _ Resolver = &IPNSResolver{}

// NewIPNSResolver constructs a new [IPNSResolver] from a [routing.ValueStore].
func NewIPNSResolver(route routing.ValueStore) *IPNSResolver {
	if route == nil {
		panic("attempt to create resolver with nil routing system")
	}

	return &IPNSResolver{
		routing: route,
	}
}

func (r *IPNSResolver) Resolve(ctx context.Context, name string, options ...ResolveOption) (path.Path, time.Duration, error) {
	ctx, span := startSpan(ctx, "IPNSResolver.Resolve", trace.WithAttributes(attribute.String("Name", name)))
	defer span.End()

	return resolve(ctx, r, name, ProcessResolveOptions(options))
}

func (r *IPNSResolver) ResolveAsync(ctx context.Context, name string, options ...ResolveOption) <-chan ResolveResult {
	ctx, span := startSpan(ctx, "IPNSResolver.ResolveAsync", trace.WithAttributes(attribute.String("Name", name)))
	defer span.End()

	return resolveAsync(ctx, r, name, ProcessResolveOptions(options))
}

func (r *IPNSResolver) resolveOnceAsync(ctx context.Context, nameStr string, options ResolveOptions) <-chan ResolveResult {
	ctx, span := startSpan(ctx, "IPNSResolver.ResolveOnceAsync", trace.WithAttributes(attribute.String("Name", nameStr)))
	defer span.End()

	out := make(chan ResolveResult, 1)
	log.Debugf("RoutingResolver resolving %s", nameStr)
	cancel := func() {}

	if options.DhtTimeout != 0 {
		// Resolution must complete within the timeout
		ctx, cancel = context.WithTimeout(ctx, options.DhtTimeout)
	}

	name, err := ipns.NameFromString(nameStr)
	if err != nil {
		log.Debugf("RoutingResolver: could not convert key %q to IPNS name: %s\n", nameStr, err)
		out <- ResolveResult{Err: err}
		close(out)
		cancel()
		return out
	}

	vals, err := r.routing.SearchValue(ctx, string(name.RoutingKey()), dht.Quorum(int(options.DhtRecordCount)))
	if err != nil {
		log.Debugf("RoutingResolver: dht get for name %s failed: %s", nameStr, err)
		out <- ResolveResult{Err: err}
		close(out)
		cancel()
		return out
	}

	go func() {
		defer cancel()
		defer close(out)
		ctx, span := startSpan(ctx, "IpnsResolver.ResolveOnceAsync.Worker")
		defer span.End()

		for {
			select {
			case val, ok := <-vals:
				if !ok {
					return
				}

				rec, err := ipns.UnmarshalRecord(val)
				if err != nil {
					log.Debugf("RoutingResolver: could not unmarshal value for name %s: %s", nameStr, err)
					emitOnceResult(ctx, out, ResolveResult{Err: err})
					return
				}

				p, err := rec.Value()
				if err != nil {
					emitOnceResult(ctx, out, ResolveResult{Err: err})
					return
				}

				ttl, err := calculateBestTTL(rec)
				if err != nil {
					emitOnceResult(ctx, out, ResolveResult{Err: err})
					return
				}

				emitOnceResult(ctx, out, ResolveResult{Path: p, TTL: ttl})
			case <-ctx.Done():
				return
			}
		}
	}()

	return out
}

func calculateBestTTL(rec *ipns.Record) (time.Duration, error) {
	ttl := DefaultResolverCacheTTL
	if recordTTL, err := rec.TTL(); err == nil {
		ttl = recordTTL
	}

	switch eol, err := rec.Validity(); err {
	case ipns.ErrUnrecognizedValidity:
		// No EOL.
	case nil:
		ttEol := time.Until(eol)
		if ttEol < 0 {
			// It *was* valid when we first resolved it.
			ttl = 0
		} else if ttEol < ttl {
			ttl = ttEol
		}
	default:
		return 0, err
	}

	return ttl, nil
}
