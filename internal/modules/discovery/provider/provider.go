package provider

import (
	"context"
)

type Provider interface {
	Name() string
	Discover(ctx context.Context, domain string) ([]string, error)
}
