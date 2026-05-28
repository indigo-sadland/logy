package exporter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/indigo-sadland/logy/internal/storage"
)

// AnytypeOptions contains connection settings plus Anytype type/property keys
// needed to map logy's stored recon data into the user's Anytype workspace.
type AnytypeOptions struct {
	Domain           string
	EngagementName   string
	DatabasePath     string
	SpaceID          string
	BaseURL          string
	Token            string
	Version          string
	DebugScanPayload bool

	EngagementTypeKey                   string
	AssetTypeKey                        string
	ServiceTypeKey                      string
	ScanTypeKey                         string
	ServiceHistoricalObservationTypeKey string

	AliasPropertyKey                                string
	EngagementPropertyKey                           string
	AssetPropertyKey                                string
	PortPropertyKey                                 string
	StatePropertyKey                                string
	ServicePropertyKey                              string
	BannerPropertyKey                               string
	ScanStatusPropertyKey                           string
	TimestampPropertyKey                            string
	HistoricalObservationNamePropertyKey            string
	HistoricalObservationServiceLinkPropertyKey     string
	HistoricalObservationPortPropertyKey            string
	HistoricalObservationObservedStatePropertyKey   string
	HistoricalObservationObservedBannerPropertyKey  string
	HistoricalObservationObservedServicePropertyKey string
	HistoricalObservationTimestampPropertyKey       string
}

// AnytypeResult summarizes the objects created during an Anytype export run.
type AnytypeResult struct {
	Domain                               string
	Engagement                           string
	EngagementID                         string
	AssetsCreated                        int
	AssetsReused                         int
	AssetsUpdated                        int
	ServicesCreated                      int
	ServicesReused                       int
	ServiceHistoricalObservationsCreated int
	ServiceHistoricalObservationsSkipped int
	ScansCreated                         int
	ScansSkipped                         int
	AnytypeSpace                         string
	AnytypeURL                           string
}

// AnytypePreview describes what an export would write before creating objects.
type AnytypePreview struct {
	Domain                        string
	Engagement                    string
	EngagementID                  string
	Assets                        int
	Services                      int
	ServiceHistoricalObservations int
	Scans                         int
	AnytypeSpace                  string
	AnytypeURL                    string
}

type anytypeClient struct {
	baseURL string
	spaceID string
	token   string
	version string
	client  *http.Client
}

type anytypeProperty map[string]any

// anytypeCreateObjectRequest matches the subset of Anytype's create-object API
// used by this exporter.
type anytypeCreateObjectRequest struct {
	TypeKey    string            `json:"type_key"`
	Name       string            `json:"name"`
	Markdown   string            `json:"markdown,omitempty"`
	Properties []anytypeProperty `json:"properties,omitempty"`
}

// anytypeUpdateObjectRequest matches the PATCH payload accepted by Anytype for
// property updates. It omits type_key because the object already exists.
type anytypeUpdateObjectRequest struct {
	Name       string            `json:"name,omitempty"`
	Markdown   string            `json:"markdown,omitempty"`
	Properties []anytypeProperty `json:"properties,omitempty"`
}

type anytypeAssetExport struct {
	IP      string
	Aliases []string
	ID      string
}

type anytypeObject struct {
	ID  string
	Raw map[string]any
}

// ExportAnytype pushes saved subdomain and port scan state into Anytype.
// It creates one Asset per IP address and one Service per saved port scan.
func ExportAnytype(ctx context.Context, opts AnytypeOptions, subdomains []storage.SubdomainRecord, scans []storage.PortScanRecord, observations []storage.ServiceHistoricalObservationRecord, runs []storage.CommandRunRecord) (AnytypeResult, error) {
	opts = NormalizeAnytypeOptions(opts)
	if err := ValidateAnytypeOptions(opts); err != nil {
		return AnytypeResult{}, err
	}

	assets := buildAnytypeAssets(subdomains, scans)
	if len(assets) == 0 {
		return AnytypeResult{}, fmt.Errorf("no resolved IP assets found for domain %s\n", opts.Domain)
	}

	client := newAnytypeClient(opts)

	engagementID, err := client.findObjectByName(ctx, opts.EngagementTypeKey, opts.EngagementName)
	if err != nil {
		return AnytypeResult{}, err
	}

	createdAssets := 0
	reusedAssets := 0
	updatedAssets := 0
	for i := range assets {
		existing, err := client.findObjectByExactName(ctx, opts.AssetTypeKey, assets[i].IP)
		if err != nil {
			return AnytypeResult{}, fmt.Errorf("search Anytype asset %s: %w", assets[i].IP, err)
		}
		if existing != nil {
			assets[i].ID = existing.ID
			reusedAssets++
			if updated, err := client.mergeAssetAliases(ctx, existing, opts.AliasPropertyKey, opts.EngagementPropertyKey, engagementID, assets[i].Aliases); err != nil {
				return AnytypeResult{}, fmt.Errorf("update Anytype asset %s aliases: %w", assets[i].IP, err)
			} else if updated {
				updatedAssets++
			}
			continue
		}

		assetID, err := client.createObject(ctx, anytypeCreateObjectRequest{
			TypeKey:    opts.AssetTypeKey,
			Name:       assets[i].IP,
			Properties: anytypeAssetProperties(opts, engagementID, assets[i].Aliases),
		})
		if err != nil {
			return AnytypeResult{}, fmt.Errorf("create Anytype asset %s: %w", assets[i].IP, err)
		}
		assets[i].ID = assetID
		createdAssets++
	}

	assetIDByIP := make(map[string]string, len(assets))
	aliasesByIP := make(map[string][]string, len(assets))
	for _, asset := range assets {
		assetIDByIP[asset.IP] = asset.ID
		aliasesByIP[asset.IP] = asset.Aliases
	}

	createdServices := 0
	reusedServices := 0
	// Reuse the same service identity later when we attach historical evidence.
	serviceIDByKey := make(map[string]string, len(scans))
	serviceNameByKey := make(map[string]string, len(scans))
	for _, scan := range scans {
		assetID := assetIDByIP[scan.IP]
		if assetID == "" {
			continue
		}
		serviceKey := anytypeServiceObservationKey(scan.IP, scan.Port, scan.Protocol)
		serviceName := anytypeServiceObjectName(scan, aliasesByIP[scan.IP])
		exists, err := client.serviceExists(ctx, opts.ServiceTypeKey, scan, aliasesByIP[scan.IP], opts.EngagementPropertyKey, engagementID)
		if err != nil {
			return AnytypeResult{}, fmt.Errorf("search Anytype service for %s:%d/%s: %w", scan.IP, scan.Port, scan.Protocol, err)
		}
		if exists {
			reusedServices++
			existing, err := client.findObjectByExactName(ctx, opts.ServiceTypeKey, serviceName)
			if err == nil && existing != nil {
				serviceIDByKey[serviceKey] = existing.ID
				serviceNameByKey[serviceKey] = serviceName
			}
			continue
		}
		serviceID, err := client.createObject(ctx, anytypeCreateObjectRequest{
			TypeKey:    opts.ServiceTypeKey,
			Name:       serviceName,
			Properties: anytypeServiceProperties(opts, engagementID, assetID, scan),
		})
		if err != nil {
			return AnytypeResult{}, fmt.Errorf("create Anytype service for %s:%d/%s: %w", scan.IP, scan.Port, scan.Protocol, err)
		}
		if serviceID != "" {
			createdServices++
			serviceIDByKey[serviceKey] = serviceID
			serviceNameByKey[serviceKey] = serviceName
		}
	}

	createdHistorical := 0
	skippedHistorical := 0
	for _, observation := range observations {
		// Historical observations only make sense when they point at a stable
		// service object from the same export run.
		serviceKey := anytypeServiceObservationKey(observation.HostIP, observation.Port, observation.Protocol)
		serviceID := serviceIDByKey[serviceKey]
		serviceName := serviceNameByKey[serviceKey]
		if serviceID == "" || serviceName == "" {
			continue
		}
		if !collidesWithCurrentService(observation, scans) {
			continue
		}
		name := anytypeHistoricalObservationName(observation, serviceName)
		exists, err := client.historicalObservationExists(ctx, opts.ServiceHistoricalObservationTypeKey, name, observation.ObservedAt, opts.HistoricalObservationTimestampPropertyKey)
		if err != nil {
			return AnytypeResult{}, fmt.Errorf("search Anytype service historical observation for %s: %w", name, err)
		}
		if exists {
			skippedHistorical++
			continue
		}
		observationID, err := client.createObject(ctx, anytypeCreateObjectRequest{
			TypeKey:    opts.ServiceHistoricalObservationTypeKey,
			Name:       name,
			Properties: anytypeHistoricalObservationProperties(opts, engagementID, serviceID, observation),
		})
		if err != nil {
			return AnytypeResult{}, fmt.Errorf("create Anytype service historical observation for %s: %w", name, err)
		}
		if observationID != "" {
			createdHistorical++
		}
	}

	createdScans := 0
	skippedScans := 0
	for _, run := range runs {
		existing, err := client.findExistingScan(ctx, opts.ScanTypeKey, run.Command, commandRunStartedAt(run), opts.TimestampPropertyKey)
		if err != nil {
			return AnytypeResult{}, fmt.Errorf("search Anytype scan for command run %d: %w", run.ID, err)
		}
		if existing != nil {
			if opts.DebugScanPayload {
				logAnytypeScanPayload(http.MethodPatch, "/v1/spaces/"+opts.SpaceID+"/objects/"+existing.ID, anytypeUpdateObjectRequest{Markdown: mustCommandRunMarkdown(run, opts.DatabasePath)})
			}
			updated, err := client.updateScanBody(ctx, existing.ID, run, opts.DatabasePath)
			if err != nil {
				return AnytypeResult{}, fmt.Errorf("update Anytype scan body for command run %d: %w", run.ID, err)
			}
			if !updated {
				skippedScans++
				continue
			}
			skippedScans++
			continue
		}
		markdown, err := commandRunMarkdown(run, opts.DatabasePath)
		if err != nil {
			return AnytypeResult{}, fmt.Errorf("build Anytype scan body for command run %d: %w", run.ID, err)
		}
		payload := anytypeCreateObjectRequest{
			TypeKey:    opts.ScanTypeKey,
			Name:       run.Command,
			Markdown:   markdown,
			Properties: anytypeCommandRunProperties(opts, engagementID, run),
		}
		if opts.DebugScanPayload {
			logAnytypeScanPayload(http.MethodPost, "/v1/spaces/"+opts.SpaceID+"/objects", payload)
		}
		scanID, err := client.createObject(ctx, payload)
		if err != nil {
			return AnytypeResult{}, fmt.Errorf("create Anytype scan for command run %d: %w", run.ID, err)
		}
		if scanID != "" {
			createdScans++
		}
	}

	return AnytypeResult{
		Domain:                               opts.Domain,
		Engagement:                           opts.EngagementName,
		EngagementID:                         engagementID,
		AssetsCreated:                        createdAssets,
		AssetsReused:                         reusedAssets,
		AssetsUpdated:                        updatedAssets,
		ServicesCreated:                      createdServices,
		ServicesReused:                       reusedServices,
		ServiceHistoricalObservationsCreated: createdHistorical,
		ServiceHistoricalObservationsSkipped: skippedHistorical,
		ScansCreated:                         createdScans,
		ScansSkipped:                         skippedScans,
		AnytypeSpace:                         opts.SpaceID,
		AnytypeURL:                           opts.BaseURL,
	}, nil
}

// PreviewAnytype resolves the target engagement and counts the objects that would be created without mutating Anytype.
func PreviewAnytype(ctx context.Context, opts AnytypeOptions, subdomains []storage.SubdomainRecord, scans []storage.PortScanRecord, observations []storage.ServiceHistoricalObservationRecord, runs []storage.CommandRunRecord) (AnytypePreview, error) {
	opts = NormalizeAnytypeOptions(opts)
	if err := ValidateAnytypeOptions(opts); err != nil {
		return AnytypePreview{}, err
	}

	assets := buildAnytypeAssets(subdomains, scans)
	if len(assets) == 0 {
		return AnytypePreview{}, fmt.Errorf("no resolved IP assets found for domain %s\n", opts.Domain)
	}

	client := newAnytypeClient(opts)
	engagementID, err := client.findObjectByName(ctx, opts.EngagementTypeKey, opts.EngagementName)
	if err != nil {
		return AnytypePreview{}, err
	}

	assetIPs := make(map[string]struct{}, len(assets))
	for _, asset := range assets {
		assetIPs[asset.IP] = struct{}{}
	}
	serviceCount := 0
	for _, scan := range scans {
		if _, ok := assetIPs[scan.IP]; ok {
			serviceCount++
		}
	}
	historicalCount := 0
	for _, observation := range observations {
		// Preview only counts observations that would produce a new historical object.
		if collidesWithCurrentService(observation, scans) {
			historicalCount++
		}
	}

	return AnytypePreview{
		Domain:                        opts.Domain,
		Engagement:                    opts.EngagementName,
		EngagementID:                  engagementID,
		Assets:                        len(assets),
		Services:                      serviceCount,
		ServiceHistoricalObservations: historicalCount,
		Scans:                         len(runs),
		AnytypeSpace:                  opts.SpaceID,
		AnytypeURL:                    opts.BaseURL,
	}, nil
}

// NormalizeAnytypeOptions trims user-provided option values and normalizes the
// base URL so request paths can be appended safely.
func NormalizeAnytypeOptions(opts AnytypeOptions) AnytypeOptions {
	opts.Domain = strings.TrimSpace(opts.Domain)
	opts.EngagementName = strings.TrimSpace(opts.EngagementName)
	opts.DatabasePath = strings.TrimSpace(opts.DatabasePath)
	opts.SpaceID = strings.TrimSpace(opts.SpaceID)
	opts.BaseURL = strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	opts.Token = strings.TrimSpace(opts.Token)
	opts.Version = strings.TrimSpace(opts.Version)
	opts.EngagementTypeKey = strings.TrimSpace(opts.EngagementTypeKey)
	opts.AssetTypeKey = strings.TrimSpace(opts.AssetTypeKey)
	opts.ServiceTypeKey = strings.TrimSpace(opts.ServiceTypeKey)
	opts.ScanTypeKey = strings.TrimSpace(opts.ScanTypeKey)
	opts.ServiceHistoricalObservationTypeKey = strings.TrimSpace(opts.ServiceHistoricalObservationTypeKey)
	opts.AliasPropertyKey = strings.TrimSpace(opts.AliasPropertyKey)
	opts.EngagementPropertyKey = strings.TrimSpace(opts.EngagementPropertyKey)
	opts.AssetPropertyKey = strings.TrimSpace(opts.AssetPropertyKey)
	opts.PortPropertyKey = strings.TrimSpace(opts.PortPropertyKey)
	opts.StatePropertyKey = strings.TrimSpace(opts.StatePropertyKey)
	opts.ServicePropertyKey = strings.TrimSpace(opts.ServicePropertyKey)
	opts.BannerPropertyKey = strings.TrimSpace(opts.BannerPropertyKey)
	opts.ScanStatusPropertyKey = strings.TrimSpace(opts.ScanStatusPropertyKey)
	opts.TimestampPropertyKey = strings.TrimSpace(opts.TimestampPropertyKey)
	opts.HistoricalObservationNamePropertyKey = strings.TrimSpace(opts.HistoricalObservationNamePropertyKey)
	opts.HistoricalObservationServiceLinkPropertyKey = strings.TrimSpace(opts.HistoricalObservationServiceLinkPropertyKey)
	opts.HistoricalObservationPortPropertyKey = strings.TrimSpace(opts.HistoricalObservationPortPropertyKey)
	opts.HistoricalObservationObservedStatePropertyKey = strings.TrimSpace(opts.HistoricalObservationObservedStatePropertyKey)
	opts.HistoricalObservationObservedBannerPropertyKey = strings.TrimSpace(opts.HistoricalObservationObservedBannerPropertyKey)
	opts.HistoricalObservationObservedServicePropertyKey = strings.TrimSpace(opts.HistoricalObservationObservedServicePropertyKey)
	opts.HistoricalObservationTimestampPropertyKey = strings.TrimSpace(opts.HistoricalObservationTimestampPropertyKey)
	return opts
}

// ValidateAnytypeOptions checks the minimum configuration required before any
// network calls are made.
func ValidateAnytypeOptions(opts AnytypeOptions) error {
	switch {
	case opts.Domain == "":
		return fmt.Errorf("--domain is required\n")
	case opts.EngagementName == "":
		return fmt.Errorf("--engagement is required\n")
	case opts.SpaceID == "":
		return fmt.Errorf("--space or ANYTYPE_SPACE_ID is required\n")
	case opts.Token == "":
		return fmt.Errorf("--token or ANYTYPE_TOKEN is required\n")
	case opts.BaseURL == "":
		return fmt.Errorf("--url or ANYTYPE_URL is required\n")
	case opts.Version == "":
		return fmt.Errorf("--anytype-version or ANYTYPE_VERSION is required\n")
	case opts.EngagementTypeKey == "" || opts.AssetTypeKey == "" || opts.ServiceTypeKey == "" || opts.ScanTypeKey == "" || opts.ServiceHistoricalObservationTypeKey == "":
		return fmt.Errorf("Anytype type keys must not be empty\n")
	case opts.ScanStatusPropertyKey == "" || opts.TimestampPropertyKey == "":
		return fmt.Errorf("Anytype scan property keys must not be empty\n")
	case opts.HistoricalObservationNamePropertyKey == "" || opts.HistoricalObservationServiceLinkPropertyKey == "" || opts.HistoricalObservationPortPropertyKey == "" || opts.HistoricalObservationObservedStatePropertyKey == "" || opts.HistoricalObservationObservedBannerPropertyKey == "" || opts.HistoricalObservationObservedServicePropertyKey == "" || opts.HistoricalObservationTimestampPropertyKey == "":
		return fmt.Errorf("Anytype service historical observation property keys must not be empty\n")
	}
	return nil
}

// anytypeCommandRunProperties builds the structured Scan properties. The actual
// command output transcript goes into the object's markdown body because the
// Anytype object API models rich page content separately from properties.
func anytypeCommandRunProperties(opts AnytypeOptions, engagementID string, run storage.CommandRunRecord) []anytypeProperty {
	return []anytypeProperty{
		selectProperty(opts.ScanStatusPropertyKey, anytypeCommandRunStatus(run.Status)),
		textProperty(opts.TimestampPropertyKey, commandRunStartedAt(run)),
		objectsProperty(opts.EngagementPropertyKey, engagementID),
	}
}

func anytypeAssetProperties(opts AnytypeOptions, engagementID string, aliases []string) []anytypeProperty {
	return []anytypeProperty{
		textProperty(opts.AliasPropertyKey, strings.Join(aliases, ", ")),
		objectsProperty(opts.EngagementPropertyKey, engagementID),
	}
}

func anytypeServiceProperties(opts AnytypeOptions, engagementID string, assetID string, scan storage.PortScanRecord) []anytypeProperty {
	return []anytypeProperty{
		textProperty(opts.PortPropertyKey, anytypePortValue(scan.Port, scan.Protocol)),
		textProperty(opts.StatePropertyKey, scan.State),
		textProperty(opts.ServicePropertyKey, formatAnytypeService(scan.Service, scan.Port)),
		textProperty(opts.BannerPropertyKey, scan.Version),
		objectsProperty(opts.EngagementPropertyKey, engagementID),
		objectsProperty(opts.AssetPropertyKey, assetID),
	}
}

func anytypeHistoricalObservationProperties(opts AnytypeOptions, engagementID string, serviceID string, observation storage.ServiceHistoricalObservationRecord) []anytypeProperty {
	return []anytypeProperty{
		objectsProperty(opts.HistoricalObservationServiceLinkPropertyKey, serviceID),
		textProperty(opts.HistoricalObservationPortPropertyKey, anytypePortValue(observation.Port, observation.Protocol)),
		textProperty(opts.HistoricalObservationObservedStatePropertyKey, observation.ObservedState),
		textProperty(opts.HistoricalObservationObservedBannerPropertyKey, observation.ObservedBanner),
		textProperty(opts.HistoricalObservationObservedServicePropertyKey, observation.ObservedService),
		textProperty(opts.HistoricalObservationTimestampPropertyKey, observation.ObservedAt.UTC().Format(time.RFC3339)),
		objectsProperty(opts.EngagementPropertyKey, engagementID),
	}
}

func buildAnytypeAssets(subdomains []storage.SubdomainRecord, scans []storage.PortScanRecord) []anytypeAssetExport {
	// Assets are IP-centric: the IP becomes the Anytype object name and all
	// resolved subdomains pointing to it become the Alias property.
	aliasesByIP := make(map[string]map[string]struct{}, len(subdomains))
	for _, record := range subdomains {
		if !record.Resolved {
			continue
		}
		for _, ip := range record.IPs {
			ip = strings.TrimSpace(ip)
			if ip == "" {
				continue
			}
			if _, ok := aliasesByIP[ip]; !ok {
				aliasesByIP[ip] = make(map[string]struct{}, 4)
			}
			aliasesByIP[ip][record.Subdomain] = struct{}{}
		}
	}
	for _, scan := range scans {
		// Raw port scans can be saved without subdomain state, so keep scanned
		// IPs as Assets even when there are no aliases for them.
		ip := strings.TrimSpace(scan.IP)
		if ip == "" {
			continue
		}
		if _, ok := aliasesByIP[ip]; !ok {
			aliasesByIP[ip] = make(map[string]struct{}, 1)
		}
	}

	ips := make([]string, 0, len(aliasesByIP))
	for ip := range aliasesByIP {
		ips = append(ips, ip)
	}
	slices.Sort(ips)

	assets := make([]anytypeAssetExport, 0, len(ips))
	for _, ip := range ips {
		aliases := make([]string, 0, len(aliasesByIP[ip]))
		for alias := range aliasesByIP[ip] {
			aliases = append(aliases, alias)
		}
		slices.Sort(aliases)
		assets = append(assets, anytypeAssetExport{IP: ip, Aliases: aliases})
	}
	return assets
}

func newAnytypeClient(opts AnytypeOptions) anytypeClient {
	return anytypeClient{
		baseURL: opts.BaseURL,
		spaceID: opts.SpaceID,
		token:   opts.Token,
		version: opts.Version,
		client:  http.DefaultClient,
	}
}

func anytypeServiceObservationKey(ip string, port int, protocol string) string {
	return strings.TrimSpace(ip) + "|" + strconv.Itoa(port) + "|" + strings.ToLower(strings.TrimSpace(protocol))
}

func anytypePortValue(port int, protocol string) string {
	return fmt.Sprintf("%d/%s", port, strings.ToLower(strings.TrimSpace(protocol)))
}

func anytypeHistoricalObservationName(observation storage.ServiceHistoricalObservationRecord, serviceName string) string {
	serviceName = strings.TrimSpace(serviceName)
	if serviceName == "" {
		// Fall back to the observation itself when no current service name was resolved.
		serviceName = anytypeServiceObservationFallbackName(observation)
	}
	return serviceName + " @ " + observation.ObservedAt.UTC().Format(time.RFC3339)
}

func collidesWithCurrentService(observation storage.ServiceHistoricalObservationRecord, scans []storage.PortScanRecord) bool {
	for _, scan := range scans {
		if strings.TrimSpace(scan.IP) != strings.TrimSpace(observation.HostIP) {
			continue
		}
		if scan.Port != observation.Port {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(scan.Protocol), strings.TrimSpace(observation.Protocol)) {
			continue
		}
		// Create historical objects only when the observation disagrees with the current service snapshot.
		if !strings.EqualFold(strings.TrimSpace(scan.State), strings.TrimSpace(observation.ObservedState)) {
			return true
		}
		if !strings.EqualFold(strings.TrimSpace(scan.Service), strings.TrimSpace(observation.ObservedService)) {
			return true
		}
		if strings.TrimSpace(scan.Version) != strings.TrimSpace(observation.ObservedBanner) {
			return true
		}
		return false
	}
	return false
}

func anytypeServiceObservationFallbackName(observation storage.ServiceHistoricalObservationRecord) string {
	target := strings.TrimSpace(observation.Hostname)
	if target == "" {
		target = strings.TrimSpace(observation.HostIP)
	}
	return fmt.Sprintf("%d %s - %s", observation.Port, formatAnytypeService(observation.ObservedService, observation.Port), target)
}

func anytypeServiceObjectName(scan storage.PortScanRecord, aliases []string) string {
	// Prefer a hostname in the display name when one exists, while still linking
	// the Service object to the IP Asset.
	target := scan.IP
	if len(aliases) > 0 {
		target = aliases[0]
	}
	return fmt.Sprintf("%d %s - %s", scan.Port, formatAnytypeService(scan.Service, scan.Port), target)
}

func anytypeServiceObjectNames(scan storage.PortScanRecord, aliases []string) []string {
	// Search both the current alias-based name and the IP fallback name so
	// services exported before hostname discovery are still reused.
	return uniqueSortedStrings([]string{
		anytypeServiceObjectName(scan, aliases),
		anytypeServiceObjectName(scan, nil),
	})
}

func formatAnytypeService(service string, port int) string {
	service = strings.ToUpper(strings.TrimSpace(service))
	if service == "" {
		return strconv.Itoa(port)
	}
	return service
}

func textProperty(key string, value string) anytypeProperty {
	return anytypeProperty{
		"key":  key,
		"text": strings.TrimSpace(value),
	}
}

func selectProperty(key string, value string) anytypeProperty {
	return anytypeProperty{
		"key":    key,
		"select": strings.TrimSpace(value),
	}
}

func objectsProperty(key string, ids ...string) anytypeProperty {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" {
			out = append(out, id)
		}
	}
	return anytypeProperty{
		"key":     key,
		"objects": out,
	}
}

func (c anytypeClient) findObjectByName(ctx context.Context, typeKey string, name string) (string, error) {
	body := map[string]any{
		"query": name,
		"types": []string{typeKey},
	}
	raw, err := c.doJSON(ctx, http.MethodPost, "/v1/spaces/"+c.spaceID+"/search?offset=0&limit=20", body)
	if err != nil {
		return "", fmt.Errorf("search Anytype engagement %q: %w", name, err)
	}
	id := extractAnytypeObjectIDByName(raw, name)
	if id == "" {
		return "", fmt.Errorf("Anytype engagement %q was not found\n", name)
	}
	return id, nil
}

func (c anytypeClient) findObjectByExactName(ctx context.Context, typeKey string, name string) (*anytypeObject, error) {
	body := map[string]any{
		"query": name,
		"types": []string{typeKey},
	}
	raw, err := c.doJSON(ctx, http.MethodPost, "/v1/spaces/"+c.spaceID+"/search?offset=0&limit=100", body)
	if err != nil {
		return nil, err
	}
	name = strings.TrimSpace(name)
	for _, candidate := range anytypeResponseObjects(raw) {
		if anytypeObjectName(candidate) != name {
			continue
		}
		id := anytypeString(candidate["id"])
		if id == "" {
			continue
		}
		full, err := c.getObject(ctx, id)
		if err != nil {
			return nil, err
		}
		return &anytypeObject{ID: id, Raw: full}, nil
	}
	return nil, nil
}

func (c anytypeClient) getObject(ctx context.Context, id string) (map[string]any, error) {
	raw, err := c.doJSON(ctx, http.MethodGet, "/v1/spaces/"+c.spaceID+"/objects/"+id, nil)
	if err != nil {
		return nil, err
	}
	return anytypeResponseObject(raw), nil
}

func (c anytypeClient) mergeAssetAliases(ctx context.Context, object *anytypeObject, aliasPropertyKey string, engagementPropertyKey string, engagementID string, aliases []string) (bool, error) {
	// Preserve aliases that users added in Anytype while appending Logy's latest
	// hostname set for the IP asset.
	existingAliases := splitAliasText(anytypePropertyString(object.Raw, aliasPropertyKey))
	mergedAliases := mergeAliasValues(existingAliases, aliases)
	if slices.Equal(existingAliases, mergedAliases) {
		return false, nil
	}
	_, err := c.updateObject(ctx, object.ID, anytypeUpdateObjectRequest{
		Properties: []anytypeProperty{
			textProperty(aliasPropertyKey, strings.Join(mergedAliases, ", ")),
			objectsProperty(engagementPropertyKey, engagementID),
		},
	})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c anytypeClient) serviceExists(ctx context.Context, typeKey string, scan storage.PortScanRecord, aliases []string, engagementPropertyKey string, engagementID string) (bool, error) {
	for _, name := range anytypeServiceObjectNames(scan, aliases) {
		existing, err := c.findObjectByExactName(ctx, typeKey, name)
		if err != nil {
			return false, err
		}
		if existing == nil {
			continue
		}
		if objectLinkedToEngagement(existing.Raw, engagementPropertyKey, engagementID) {
			return true, nil
		}
	}
	return false, nil
}

func (c anytypeClient) findExistingScan(ctx context.Context, typeKey string, command string, startedAt string, timestampPropertyKey string) (*anytypeObject, error) {
	body := map[string]any{
		"query": command,
		"types": []string{typeKey},
	}
	raw, err := c.doJSON(ctx, http.MethodPost, "/v1/spaces/"+c.spaceID+"/search?offset=0&limit=100", body)
	if err != nil {
		return nil, err
	}
	command = strings.TrimSpace(command)
	for _, candidate := range anytypeResponseObjects(raw) {
		if anytypeString(candidate["name"]) != command {
			continue
		}
		timestamp := anytypePropertyString(candidate, timestampPropertyKey)
		if timestamp == "" || timestamp == startedAt {
			id := anytypeString(candidate["id"])
			if id == "" {
				continue
			}
			return &anytypeObject{ID: id, Raw: candidate}, nil
		}
	}
	return nil, nil
}

func (c anytypeClient) historicalObservationExists(ctx context.Context, typeKey string, name string, observedAt time.Time, timestampPropertyKey string) (bool, error) {
	body := map[string]any{
		"query": name,
		"types": []string{typeKey},
	}
	raw, err := c.doJSON(ctx, http.MethodPost, "/v1/spaces/"+c.spaceID+"/search?offset=0&limit=100", body)
	if err != nil {
		return false, err
	}
	wantName := strings.TrimSpace(name)
	wantTimestamp := observedAt.UTC().Format(time.RFC3339)
	for _, candidate := range anytypeResponseObjects(raw) {
		if anytypeString(candidate["name"]) != wantName {
			continue
		}
		if anytypePropertyString(candidate, timestampPropertyKey) == wantTimestamp {
			return true, nil
		}
	}
	return false, nil
}

// updateScanBody patches the object markdown for an existing Scan so rerunning
// export corrects older objects that stored command output in the wrong place.
func (c anytypeClient) updateScanBody(ctx context.Context, id string, run storage.CommandRunRecord, databasePath string) (bool, error) {
	markdown, err := commandRunMarkdown(run, databasePath)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(markdown) == "" {
		return false, nil
	}
	current, err := c.getObject(ctx, id)
	if err != nil {
		return false, err
	}
	if strings.TrimSpace(anytypeString(current["markdown"])) == strings.TrimSpace(markdown) {
		return false, nil
	}
	_, err = c.updateObject(ctx, id, anytypeUpdateObjectRequest{Markdown: markdown})
	if err != nil {
		return false, err
	}
	return true, nil
}

func (c anytypeClient) createObject(ctx context.Context, payload anytypeCreateObjectRequest) (string, error) {
	raw, err := c.doJSON(ctx, http.MethodPost, "/v1/spaces/"+c.spaceID+"/objects", payload)
	if err != nil {
		return "", err
	}
	id := extractAnytypeCreatedObjectID(raw)
	if id == "" {
		return "", fmt.Errorf("Anytype response did not include created object id")
	}
	return id, nil
}

func (c anytypeClient) updateObject(ctx context.Context, id string, payload anytypeUpdateObjectRequest) (map[string]any, error) {
	return c.doJSON(ctx, http.MethodPatch, "/v1/spaces/"+c.spaceID+"/objects/"+id, payload)
}

func (c anytypeClient) doJSON(ctx context.Context, method string, path string, payload any) (map[string]any, error) {
	var body io.Reader
	if payload != nil {
		rawPayload, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(rawPayload)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Anytype-Version", c.version)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("Anytype API returned %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}

	var out map[string]any
	if len(bytes.TrimSpace(raw)) == 0 {
		return map[string]any{}, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode Anytype response: %w", err)
	}
	return out, nil
}

func extractAnytypeObjectIDByName(raw map[string]any, wantName string) string {
	// Search response envelopes have changed across Anytype API builds, so the
	// extraction helpers accept the common array field names we have seen.
	candidates := anytypeResponseObjects(raw)
	if len(candidates) == 0 {
		return ""
	}

	wantName = strings.TrimSpace(wantName)
	for _, candidate := range candidates {
		if strings.EqualFold(anytypeString(candidate["name"]), wantName) {
			if id := anytypeString(candidate["id"]); id != "" {
				return id
			}
		}
	}
	return ""
}

func anytypeResponseObjects(raw map[string]any) []map[string]any {
	for _, key := range []string{"data", "objects", "results", "items"} {
		items, ok := raw[key].([]any)
		if !ok {
			continue
		}
		out := make([]map[string]any, 0, len(items))
		for _, item := range items {
			if object, ok := item.(map[string]any); ok {
				out = append(out, object)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

func anytypeResponseObject(raw map[string]any) map[string]any {
	for _, key := range []string{"object", "data"} {
		if object, ok := raw[key].(map[string]any); ok {
			return object
		}
	}
	return raw
}

func extractAnytypeCreatedObjectID(raw map[string]any) string {
	// Create responses may return the id at the top level or under an object-ish
	// envelope depending on API version.
	for _, key := range []string{"id", "object_id"} {
		if id := anytypeString(raw[key]); id != "" {
			return id
		}
	}
	for _, key := range []string{"object", "data"} {
		object, ok := raw[key].(map[string]any)
		if !ok {
			continue
		}
		for _, idKey := range []string{"id", "object_id"} {
			if id := anytypeString(object[idKey]); id != "" {
				return id
			}
		}
	}
	return ""
}

func anytypeObjectName(object map[string]any) string {
	for _, key := range []string{"name", "snippet"} {
		if name := anytypeString(object[key]); name != "" {
			return name
		}
	}
	return ""
}

func anytypeString(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	default:
		return ""
	}
}

func anytypePropertyString(object map[string]any, key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if direct := anytypeString(object[key]); direct != "" {
		return direct
	}
	for _, containerKey := range []string{"properties", "details"} {
		switch values := object[containerKey].(type) {
		case map[string]any:
			if value := anytypePropertyValueString(values[key]); value != "" {
				return value
			}
		case []any:
			for _, item := range values {
				property, ok := item.(map[string]any)
				if !ok || anytypeString(property["key"]) != key {
					continue
				}
				if value := anytypePropertyValueString(property); value != "" {
					return value
				}
			}
		}
	}
	return ""
}

func anytypePropertyValueString(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		for _, key := range []string{"text", "select", "value"} {
			if out := anytypeString(v[key]); out != "" {
				return out
			}
		}
	}
	return ""
}

func objectLinkedToEngagement(object map[string]any, key string, engagementID string) bool {
	ids := anytypePropertyObjectIDs(object, key)
	if len(ids) == 0 {
		// Some search/get responses omit relation values. Name match is still the
		// best available signal, but engagement is verified whenever present.
		return true
	}
	for _, id := range ids {
		if id == engagementID {
			return true
		}
	}
	return false
}

func anytypePropertyObjectIDs(object map[string]any, key string) []string {
	key = strings.TrimSpace(key)
	if key == "" {
		return nil
	}
	if ids := anytypeObjectIDs(object[key]); len(ids) > 0 {
		return ids
	}
	for _, containerKey := range []string{"properties", "details"} {
		switch values := object[containerKey].(type) {
		case map[string]any:
			if ids := anytypeObjectIDs(values[key]); len(ids) > 0 {
				return ids
			}
		case []any:
			for _, item := range values {
				property, ok := item.(map[string]any)
				if !ok || anytypeString(property["key"]) != key {
					continue
				}
				if ids := anytypeObjectIDs(property); len(ids) > 0 {
					return ids
				}
			}
		}
	}
	return nil
}

func anytypeObjectIDs(value any) []string {
	switch v := value.(type) {
	case string:
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return []string{trimmed}
		}
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if id := anytypeString(item); id != "" {
				out = append(out, id)
			}
		}
		return out
	case map[string]any:
		for _, key := range []string{"objects", "object_ids", "ids"} {
			if ids := anytypeObjectIDs(v[key]); len(ids) > 0 {
				return ids
			}
		}
	}
	return nil
}

func splitAliasText(value string) []string {
	parts := strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == '\n' })
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return uniqueSortedStrings(out)
}

func mergeAliasValues(groups ...[]string) []string {
	values := make([]string, 0, 16)
	for _, group := range groups {
		values = append(values, group...)
	}
	return uniqueSortedStrings(values)
}

func uniqueSortedStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	slices.Sort(out)
	return out
}

func anytypeCommandRunStatus(status string) string {
	if strings.EqualFold(strings.TrimSpace(status), "completed") {
		return "completed"
	}
	return "failed"
}

func commandRunStartedAt(run storage.CommandRunRecord) string {
	if run.StartedAt.IsZero() {
		return ""
	}
	return run.StartedAt.UTC().Format(time.RFC3339)
}

func commandRunTranscriptText(run storage.CommandRunRecord, databasePath string) (string, bool, error) {
	path := resolveTranscriptPath(run, databasePath)
	if path == "" {
		return "", false, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, err
	}
	return string(data), true, nil
}

// commandRunMarkdown renders the recorded terminal session as a fenced code
// block in the object's markdown body. Four backticks are used so the export
// remains valid even when the transcript itself contains triple-backtick text.
func commandRunMarkdown(run storage.CommandRunRecord, databasePath string) (string, error) {
	output, ok, err := commandRunTranscriptText(run, databasePath)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", nil
	}
	output = strings.TrimRight(output, "\n")
	if output == "" {
		return "", nil
	}
	return "````text\n" + output + "\n````", nil
}

func resolveTranscriptPath(run storage.CommandRunRecord, databasePath string) string {
	path := strings.TrimSpace(run.TranscriptPath)
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return path
	}
	baseDir := filepath.Dir(strings.TrimSpace(databasePath))
	if baseDir == "" || baseDir == "." {
		return path
	}
	return filepath.Join(baseDir, path)
}

// mustCommandRunMarkdown is used only for debug logging. Export still performs
// the real error handling on the main path; this helper just keeps the debug
// payload printable even when transcript rendering fails.
func mustCommandRunMarkdown(run storage.CommandRunRecord, databasePath string) string {
	markdown, err := commandRunMarkdown(run, databasePath)
	if err != nil {
		return "logy debug: failed to render transcript markdown: " + err.Error()
	}
	return markdown
}

// logAnytypeScanPayload prints the final request body for Scan object
// create/update operations so export debugging can confirm the exact markdown
// body Anytype receives.
func logAnytypeScanPayload(method string, path string, payload any) {
	raw, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "logy anytype debug %s %s payload marshal error: %v\n", method, path, err)
		return
	}
	fmt.Fprintf(os.Stderr, "logy anytype debug %s %s\n%s\n", method, path, string(raw))
}
