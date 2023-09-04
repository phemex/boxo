package namesys

import (
	"context"
	"errors"
	"fmt"
	"net"
	gopath "path"
	"strings"
	"time"

	"github.com/ipfs/boxo/ipns"
	path "github.com/ipfs/boxo/path"
	"github.com/ipfs/go-cid"
	dns "github.com/miekg/dns"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// LookupTXTFunc is a function that lookups TXT record values.
type LookupTXTFunc func(ctx context.Context, name string) (txt []string, err error)

// DNSResolver implements [Resolver] on DNS domains.
type DNSResolver struct {
	lookupTXT LookupTXTFunc
}

var _ Resolver = &DNSResolver{}

// NewDNSResolver constructs a name resolver using DNS TXT records.
func NewDNSResolver(lookup LookupTXTFunc) *DNSResolver {
	return &DNSResolver{lookupTXT: lookup}
}

func (r *DNSResolver) Resolve(ctx context.Context, name string, options ...ResolveOption) (path.Path, time.Duration, error) {
	ctx, span := startSpan(ctx, "DNSResolver.Resolve")
	defer span.End()

	return resolve(ctx, r, name, ProcessResolveOptions(options))
}

func (r *DNSResolver) ResolveAsync(ctx context.Context, name string, options ...ResolveOption) <-chan ResolveResult {
	ctx, span := startSpan(ctx, "DNSResolver.ResolveAsync")
	defer span.End()

	return resolveAsync(ctx, r, name, ProcessResolveOptions(options))
}

func (r *DNSResolver) resolveOnceAsync(ctx context.Context, name string, options ResolveOptions) <-chan ResolveResult {
	ctx, span := startSpan(ctx, "DNSResolver.ResolveOnceAsync")
	defer span.End()

	var fqdn string
	out := make(chan ResolveResult, 1)
	name = strings.TrimPrefix(name, ipns.NamespacePrefix)
	segments := strings.SplitN(name, "/", 2)
	domain := segments[0]

	if _, ok := dns.IsDomainName(domain); !ok {
		out <- ResolveResult{Err: fmt.Errorf("not a valid domain name: %q", domain)}
		close(out)
		return out
	}
	log.Debugf("DNSResolver resolving %s", domain)

	if strings.HasSuffix(domain, ".") {
		fqdn = domain
	} else {
		fqdn = domain + "."
	}

	rootChan := make(chan ResolveResult, 1)
	go workDomain(ctx, r, fqdn, rootChan)

	subChan := make(chan ResolveResult, 1)
	go workDomain(ctx, r, "_dnslink."+fqdn, subChan)

	appendPath := func(p path.Path) (path.Path, error) {
		if len(segments) > 1 {
			return path.Join(p, segments[1])
		}
		return p, nil
	}

	go func() {
		defer close(out)
		ctx, span := startSpan(ctx, "DNSResolver.ResolveOnceAsync.Worker")
		defer span.End()

		var rootResErr, subResErr error
		for {
			select {
			case subRes, ok := <-subChan:
				if !ok {
					subChan = nil
					break
				}
				if subRes.Err == nil {
					p, err := appendPath(subRes.Path)
					emitOnceResult(ctx, out, ResolveResult{Path: p, Err: err})
					// Return without waiting for rootRes, since this result
					// (for "_dnslink."+fqdn) takes precedence
					return
				}
				subResErr = subRes.Err
			case rootRes, ok := <-rootChan:
				if !ok {
					rootChan = nil
					break
				}
				if rootRes.Err == nil {
					p, err := appendPath(rootRes.Path)
					emitOnceResult(ctx, out, ResolveResult{Path: p, Err: err})
					// Do not return here.  Wait for subRes so that it is
					// output last if good, thereby giving subRes precedence.
				} else {
					rootResErr = rootRes.Err
				}
			case <-ctx.Done():
				return
			}
			if subChan == nil && rootChan == nil {
				// If here, then both lookups are done
				//
				// If both lookups failed due to no TXT records with a
				// dnslink, then output a more specific error message
				if rootResErr == ErrResolveFailed && subResErr == ErrResolveFailed {
					// Wrap error so that it can be tested if it is a ErrResolveFailed
					err := fmt.Errorf("%w: _dnslink subdomain at %q is missing a TXT record (https://docs.ipfs.tech/concepts/dnslink/)", ErrResolveFailed, gopath.Base(name))
					emitOnceResult(ctx, out, ResolveResult{Err: err})
				}
				return
			}
		}
	}()

	return out
}

func workDomain(ctx context.Context, r *DNSResolver, name string, res chan ResolveResult) {
	ctx, span := startSpan(ctx, "DNSResolver.WorkDomain", trace.WithAttributes(attribute.String("Name", name)))
	defer span.End()

	defer close(res)

	txt, err := r.lookupTXT(ctx, name)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			// If no TXT records found, return same error as when no text
			// records contain dnslink. Otherwise, return the actual error.
			if dnsErr.IsNotFound {
				err = ErrResolveFailed
			}
		}
		// Could not look up any text records for name
		res <- ResolveResult{Err: err}
		return
	}

	for _, t := range txt {
		p, err := parseEntry(t)
		if err == nil {
			res <- ResolveResult{Path: p}
			return
		}
	}

	// There were no TXT records with a dnslink
	res <- ResolveResult{Err: ErrResolveFailed}
}

func parseEntry(txt string) (path.Path, error) {
	p, err := path.NewPath(txt) // bare IPFS multihashes
	if err == nil {
		return p, nil
	}

	// Support legacy DNSLink entries composed by the CID only.
	if cid, err := cid.Decode(txt); err == nil {
		return path.NewIPFSPath(cid), nil
	}

	return tryParseDNSLink(txt)
}

func tryParseDNSLink(txt string) (path.Path, error) {
	parts := strings.SplitN(txt, "=", 2)
	if len(parts) == 2 && parts[0] == "dnslink" {
		p, err := path.NewPath(parts[1])
		if err == nil {
			return p, nil
		}

		// Support legacy DNSLink entries composed by "dnslink={CID}".
		if cid, err := cid.Decode(parts[1]); err == nil {
			return path.NewIPFSPath(cid), nil
		}
	}

	return nil, errors.New("not a valid dnslink entry")
}
