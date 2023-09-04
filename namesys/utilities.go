package namesys

import (
	"context"
	"fmt"
	"time"

	"github.com/ipfs/boxo/path"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

type resolver interface {
	resolveOnceAsync(ctx context.Context, name string, options ResolveOptions) <-chan ResolveResult
}

// resolve is a helper for implementing Resolver.ResolveN using resolveOnce.
func resolve(ctx context.Context, r resolver, name string, options ResolveOptions) (p path.Path, ttl time.Duration, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	err = ErrResolveFailed
	resCh := resolveAsync(ctx, r, name, options)

	for res := range resCh {
		p, ttl, err = res.Path, res.TTL, res.Err
		if err != nil {
			break
		}
	}

	return p, ttl, err
}

func resolveAsync(ctx context.Context, r resolver, name string, options ResolveOptions) <-chan ResolveResult {
	ctx, span := startSpan(ctx, "ResolveAsync")
	defer span.End()

	resCh := r.resolveOnceAsync(ctx, name, options)
	depth := options.Depth
	outCh := make(chan ResolveResult, 1)

	go func() {
		defer close(outCh)
		ctx, span := startSpan(ctx, "ResolveAsync.Worker")
		defer span.End()

		var subCh <-chan ResolveResult
		var cancelSub context.CancelFunc
		defer func() {
			if cancelSub != nil {
				cancelSub()
			}
		}()

		for {
			select {
			case res, ok := <-resCh:
				if !ok {
					resCh = nil
					break
				}

				if res.Err != nil {
					emitResult(ctx, outCh, res)
					return
				}

				log.Debugf("resolved %s to %s", name, res.Path.String())

				if !res.Path.Namespace().Mutable() {
					emitResult(ctx, outCh, res)
					break
				}

				if depth == 1 {
					res.Err = ErrResolveRecursion
					emitResult(ctx, outCh, res)
					break
				}

				subOpts := options
				if subOpts.Depth > 1 {
					subOpts.Depth--
				}

				var subCtx context.Context
				if cancelSub != nil {
					// Cancel previous recursive resolve since it won't be used anyways
					cancelSub()
				}

				subCtx, cancelSub = context.WithCancel(ctx)
				_ = cancelSub

				subCh = resolveAsync(subCtx, r, res.Path.String(), subOpts)
			case res, ok := <-subCh:
				if !ok {
					subCh = nil
					break
				}

				// We don't bother returning here in case of context timeout as there is
				// no good reason to do that, and we may still be able to emit a result
				emitResult(ctx, outCh, res)
			case <-ctx.Done():
				return
			}
			if resCh == nil && subCh == nil {
				return
			}
		}
	}()
	return outCh
}

func emitResult(ctx context.Context, outCh chan<- ResolveResult, r ResolveResult) {
	select {
	case outCh <- r:
	case <-ctx.Done():
	}
}

var tracer = otel.Tracer("boxo/namesys")

func startSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return tracer.Start(ctx, fmt.Sprintf("Namesys.%s", name))
}
