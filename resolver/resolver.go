package resolver

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/dgraph-io/ristretto"
	"github.com/pkg/errors"
)

// CacheTTL is the duration before a domain name resolution is evict form the cache.
const CacheTTL = 12 * time.Hour

// ErrHostRejected is returned when the host has been flagged as unwanted.
var ErrHostRejected = errors.New("rejected host")

// A NameResolver is used for name resolution.
type NameResolver struct {
	mu            sync.Mutex
	rejects       *urlfilter.DNSEngine
	rejectedByIPs map[string]string
	overrides     map[string]net.IP
	cache         *ristretto.Cache
}

// New return a new NameResolver.
func New(rejects []string) (*NameResolver, error) {
	rs, err := filterlist.NewRuleStorage([]filterlist.RuleList{
		&filterlist.StringRuleList{
			ID:        42,
			RulesText: strings.Join(rejects, "\n"),
		},
	})
	if err != nil {
		return nil, err
	}

	cache, err := ristretto.NewCache(&ristretto.Config{
		NumCounters: 50_000,
		MaxCost:     5000,
		BufferItems: 64,
	})
	if err != nil {
		return nil, err
	}

	return &NameResolver{
		rejects:       urlfilter.NewDNSEngine(rs),
		rejectedByIPs: map[string]string{},
		overrides:     map[string]net.IP{},
		cache:         cache,
	}, nil
}

// OverrideHost adds an host override.
func (r *NameResolver) OverrideHost(host string, ip string) error {
	override := net.ParseIP(ip)
	if override == nil {
		return errors.Errorf("failed to parse ip: %q", ip)
	}

	r.overrides[host] = override
	return nil
}

// Resolve returns the ip for the given domain name.
func (r *NameResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	if ip, ok := r.cache.Get(name); ok {
		return ctx, ip.(net.IP), nil
	}

	if ip, ok := r.isRejectedByIP(name); ok {
		return ctx, nil, errors.Wrapf(ErrHostRejected, "[cached domain/ip] %s/%s", name, ip)
	}

	//

	if rules, ok := r.rejects.Match(name); ok {
		if rules.NetworkRule != nil {
			return ctx, nil, errors.Wrapf(ErrHostRejected, "[domain][%s] %s", rules.NetworkRule.String(), name)
		}
		return ctx, nil, errors.Wrapf(ErrHostRejected, "[domain] %s", name)
	}

	if ip, ok := r.overrides[name]; ok {
		return ctx, ip, nil
	}

	addr, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return ctx, nil, errors.Wrapf(err, "[resolve] %s", name)
	}

	if rules, ok := r.rejects.Match(addr.IP.String()); ok {
		r.setRejectedByIP(name, addr.IP)
		if rules.NetworkRule != nil {
			return ctx, nil, errors.Wrapf(ErrHostRejected, "[domain/ip][%s] %s/%s", rules.NetworkRule.String(), rules.NetworkRule.String(), name)
		}
		return ctx, nil, errors.Wrapf(ErrHostRejected, "[domain/ip] %s/%s", name, addr.IP)
	}

	//

	r.cache.SetWithTTL(name, addr.IP, 1, CacheTTL)
	return ctx, addr.IP, nil
}

func (r *NameResolver) isRejectedByIP(name string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	ip, ok := r.rejectedByIPs[name]
	return ip, ok
}

func (r *NameResolver) setRejectedByIP(name string, ip net.IP) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.rejectedByIPs[name] = ip.String()
}
