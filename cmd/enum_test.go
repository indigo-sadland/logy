package cmd

import (
	"github.com/indigo-sadland/logy/internal/modules/discovery/provider"
	"testing"
)

func TestResolveEnumTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		domain        string
		asn           string
		domainFilter  string
		wantTarget    string
		wantType      string
		wantMatch     string
		wantErrString string
	}{
		{
			name:       "domain target",
			domain:     "example.com",
			wantTarget: "example.com",
			wantType:   "domain",
			wantMatch:  "example.com",
		},
		{
			name:       "asn target without filter",
			asn:        "AS3333",
			wantTarget: "AS3333",
			wantType:   "asn",
			wantMatch:  "",
		},
		{
			name:         "asn target with filter",
			asn:          "AS3333",
			domainFilter: "example.com",
			wantTarget:   "AS3333",
			wantType:     "asn",
			wantMatch:    "example.com",
		},
		{
			name:          "missing target",
			wantErrString: "at least one of --domain or --asn is required",
		},
		{
			name:          "domain and asn together",
			domain:        "example.com",
			asn:           "AS3333",
			wantErrString: "--domain and --asn are mutually exclusive; use --domain-filter with --asn",
		},
		{
			name:          "filter without asn",
			domainFilter:  "example.com",
			wantErrString: "--domain-filter requires --asn",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			gotTarget, gotType, gotMatch, err := resolveEnumTarget(tt.domain, tt.asn, tt.domainFilter)
			if tt.wantErrString != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErrString)
				}
				if err.Error() != tt.wantErrString {
					t.Fatalf("error=%q; want %q", err.Error(), tt.wantErrString)
				}
				return
			}

			if err != nil {
				t.Fatalf("resolveEnumTarget: %v", err)
			}
			if gotTarget != tt.wantTarget || gotType != tt.wantType || gotMatch != tt.wantMatch {
				t.Fatalf("got target=%q type=%q match=%q; want target=%q type=%q match=%q",
					gotTarget, gotType, gotMatch, tt.wantTarget, tt.wantType, tt.wantMatch)
			}
		})
	}
}

func TestValidateEnumProviders(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		providers     []provider.Provider
		targetType    string
		wantErrString string
	}{
		{
			name: "domain providers ok",
			providers: []provider.Provider{
				provider.NewCommandProvider("subfinder", nil),
			},
			targetType: "domain",
		},
		{
			name: "asn requires ripestat only",
			providers: []provider.Provider{
				provider.NewCommandProvider("subfinder", nil),
			},
			targetType:    "asn",
			wantErrString: "--asn scans support only the ripestat discovery provider; disable subfinder in your config file",
		},
		{
			name: "ripestat invalid for domain mode",
			providers: []provider.Provider{
				provider.NewCommandProvider("ripestat", nil),
			},
			targetType:    "domain",
			wantErrString: "ripestat requires --asn; remove it from enabled discovery tools or run with --asn",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := validateEnumProviders(tt.providers, tt.targetType)
			if tt.wantErrString != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tt.wantErrString)
				}
				if err.Error() != tt.wantErrString {
					t.Fatalf("error=%q; want %q", err.Error(), tt.wantErrString)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateEnumProviders: %v", err)
			}
		})
	}
}
