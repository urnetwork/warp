package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
)

// cloudflareProvider reconciles a cloudflare zone through the v4 api. A
// cloudflare record is one address (or one cname) per record, without
// weights or health checks: the lb set becomes round robin, and a single
// family alias becomes the target's addresses of that family.
type cloudflareProvider struct {
	ctx     context.Context
	client  *http.Client
	baseUrl string
	token   string
}

const cloudflareApiUrl = "https://api.cloudflare.com/client/v4"

// cloudflareToken finds the api token: the CLOUDFLARE_API_TOKEN environment
// variable, else the first line of the token file.
func cloudflareToken(tokenFile string) (string, error) {
	if token := strings.TrimSpace(os.Getenv("CLOUDFLARE_API_TOKEN")); token != "" {
		return token, nil
	}
	if tokenFile == "" {
		return "", fmt.Errorf("no cloudflare token: set CLOUDFLARE_API_TOKEN or pass --cloudflare-token-file")
	}
	data, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("cloudflare token file: %w", err)
	}
	token := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
	if token == "" {
		return "", fmt.Errorf("cloudflare token file %s is empty", tokenFile)
	}
	return token, nil
}

func newCloudflareProvider(ctx context.Context, token string) *cloudflareProvider {
	return &cloudflareProvider{ctx: ctx, client: http.DefaultClient, baseUrl: cloudflareApiUrl, token: token}
}

type cloudflareEnvelope struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result     json.RawMessage `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (self *cloudflareProvider) call(method string, path string, query url.Values, body any) (*cloudflareEnvelope, error) {
	requestUrl := self.baseUrl + path
	if len(query) > 0 {
		requestUrl += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(self.ctx, method, requestUrl, reader)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", "Bearer "+self.token)
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := self.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("cloudflare %s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("cloudflare %s %s: %w", method, path, err)
	}
	envelope := &cloudflareEnvelope{}
	if err := json.Unmarshal(data, envelope); err != nil {
		return nil, fmt.Errorf("cloudflare %s %s: status %d: %s", method, path, response.StatusCode, strings.TrimSpace(string(data)))
	}
	if !envelope.Success {
		messages := []string{}
		for _, apiError := range envelope.Errors {
			messages = append(messages, fmt.Sprintf("%d %s", apiError.Code, apiError.Message))
		}
		return nil, fmt.Errorf("cloudflare %s %s: %s", method, path, strings.Join(messages, "; "))
	}
	return envelope, nil
}

func (self *cloudflareProvider) zoneId(domain string) (string, error) {
	envelope, err := self.call(http.MethodGet, "/zones", url.Values{"name": {domain}}, nil)
	if err != nil {
		return "", err
	}
	zones := []struct {
		Id   string `json:"id"`
		Name string `json:"name"`
	}{}
	if err := json.Unmarshal(envelope.Result, &zones); err != nil {
		return "", fmt.Errorf("cloudflare zones: %w", err)
	}
	for _, zone := range zones {
		if strings.ToLower(zone.Name) == domain {
			return zone.Id, nil
		}
	}
	return "", fmt.Errorf("cloudflare has no zone for %s", domain)
}

// cloudflareRecord is one record, desired or observed.
type cloudflareRecord struct {
	Id      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Ttl     int    `json:"ttl"`
	Proxied bool   `json:"proxied"`
	Comment string `json:"comment,omitempty"`
}

func (r *cloudflareRecord) key() string {
	return r.Type + "|" + r.Name + "|" + strings.ToLower(r.Content)
}

func (r *cloudflareRecord) String() string {
	proxied := ""
	if r.Proxied {
		proxied = " proxied"
	}
	return fmt.Sprintf("%s %s %s ttl=%d%s", r.Type, r.Name, r.Content, r.Ttl, proxied)
}

// cloudflareDesired renders the derived names of a domain as records.
func cloudflareDesired(domain *dnsDomain, input dnsPlanInput) []*cloudflareRecord {
	ttl := input.ServicesConfig.GetDnsTtl()
	comment := "warpctl dns " + input.Env
	records := []*cloudflareRecord{}
	addAddresses := func(name string, ipv4s []string, ipv6s []string) {
		for _, address := range sortedCopy(ipv4s) {
			records = append(records, &cloudflareRecord{Type: "A", Name: name, Content: address, Ttl: ttl, Comment: comment})
		}
		for _, address := range sortedCopy(ipv6s) {
			records = append(records, &cloudflareRecord{Type: "AAAA", Name: name, Content: address, Ttl: ttl, Comment: comment})
		}
	}
	for _, name := range domain.Names {
		switch name.Kind {
		case dnsAddresses:
			ipv4s, ipv6s := name.Ipv4, name.Ipv6
			if !name.HasIpv4 {
				ipv4s = nil
			}
			if !name.HasIpv6 {
				ipv6s = nil
			}
			addAddresses(name.Name, ipv4s, ipv6s)
		case dnsLbSet:
			ipv4s, ipv6s := []string{}, []string{}
			for _, member := range name.Members {
				ipv4s = append(ipv4s, member.Ipv4)
				if member.Ipv6 != "" {
					ipv6s = append(ipv6s, member.Ipv6)
				}
			}
			addAddresses(name.Name, ipv4s, ipv6s)
		case dnsAliasTo:
			if name.HasIpv4 && name.HasIpv6 {
				records = append(records, &cloudflareRecord{Type: "CNAME", Name: name.Name, Content: name.Target, Ttl: ttl, Comment: comment})
				continue
			}
			// a single family name cannot be a cname: carry the target's
			// addresses of that family
			addAddresses(name.Name, name.Ipv4, name.Ipv6)
		}
	}
	return records
}

func (self *cloudflareProvider) observed(zoneId string, managed map[string]bool) ([]*cloudflareRecord, error) {
	records := []*cloudflareRecord{}
	for page := 1; ; page++ {
		envelope, err := self.call(http.MethodGet, "/zones/"+zoneId+"/dns_records", url.Values{"per_page": {"100"}, "page": {fmt.Sprint(page)}}, nil)
		if err != nil {
			return nil, err
		}
		pageRecords := []*cloudflareRecord{}
		if err := json.Unmarshal(envelope.Result, &pageRecords); err != nil {
			return nil, fmt.Errorf("cloudflare records: %w", err)
		}
		for _, record := range pageRecords {
			record.Name = strings.ToLower(record.Name)
			switch record.Type {
			case "A", "AAAA", "CNAME":
			default:
				continue
			}
			if managed[record.Name] {
				records = append(records, record)
			}
		}
		if envelope.ResultInfo.TotalPages <= page || len(pageRecords) == 0 {
			break
		}
	}
	return records, nil
}

type cloudflareReconciliation struct {
	zoneId  string
	creates []*cloudflareRecord
	updates []*cloudflareRecord
	deletes []*cloudflareRecord
	changes []dnsChange
}

func (self *cloudflareProvider) reconcile(domain *dnsDomain, input dnsPlanInput) (*cloudflareReconciliation, error) {
	desired := cloudflareDesired(domain, input)
	zoneId, err := self.zoneId(domain.Domain)
	if err != nil {
		return nil, err
	}
	managed := map[string]bool{}
	for _, record := range desired {
		managed[record.Name] = true
	}
	observed, err := self.observed(zoneId, managed)
	if err != nil {
		return nil, err
	}
	reconciliation := &cloudflareReconciliation{zoneId: zoneId}
	observedByKey := map[string]*cloudflareRecord{}
	// whether the name is proxied today: the sync never flips the proxy
	// setting of a name, and a new name starts unproxied
	proxiedNames := map[string]bool{}
	for _, record := range observed {
		observedByKey[record.key()] = record
		if record.Proxied {
			proxiedNames[record.Type+"|"+record.Name] = true
		}
	}
	for _, record := range desired {
		if proxiedNames[record.Type+"|"+record.Name] {
			// a proxied record carries the automatic ttl
			record.Proxied = true
			record.Ttl = 1
		}
	}
	desiredByKey := map[string]bool{}
	for _, record := range desired {
		desiredByKey[record.key()] = true
		existing, ok := observedByKey[record.key()]
		if !ok {
			reconciliation.creates = append(reconciliation.creates, record)
			reconciliation.changes = append(reconciliation.changes, dnsChange{Op: "+", What: record.String()})
			continue
		}
		if existing.Ttl != record.Ttl || existing.Proxied != record.Proxied || existing.Comment != record.Comment {
			record.Id = existing.Id
			reconciliation.updates = append(reconciliation.updates, record)
			reconciliation.changes = append(reconciliation.changes, dnsChange{Op: "~", What: record.String() + " (was " + existing.String() + ")"})
		}
	}
	for _, record := range observed {
		if desiredByKey[record.key()] {
			continue
		}
		reconciliation.deletes = append(reconciliation.deletes, record)
		reconciliation.changes = append(reconciliation.changes, dnsChange{Op: "-", What: record.String()})
	}
	for _, name := range domain.Names {
		if name.Kind == dnsLbSet {
			weighted := false
			for _, member := range name.Members {
				if member.Weight != name.Members[0].Weight {
					weighted = true
				}
			}
			if weighted {
				domain.Notes = append(domain.Notes, fmt.Sprintf("%s: cloudflare records carry no weight; the set is round robin", name.Name))
			}
		}
	}
	sort.Slice(reconciliation.changes, func(i int, j int) bool {
		return reconciliation.changes[i].What < reconciliation.changes[j].What
	})
	return reconciliation, nil
}

func (self *cloudflareProvider) Plan(domain *dnsDomain, input dnsPlanInput) ([]dnsChange, error) {
	reconciliation, err := self.reconcile(domain, input)
	if err != nil {
		return nil, err
	}
	return reconciliation.changes, nil
}

func (self *cloudflareProvider) Apply(domain *dnsDomain, input dnsPlanInput) ([]dnsChange, error) {
	reconciliation, err := self.reconcile(domain, input)
	if err != nil {
		return nil, err
	}
	// deletes first: a cname cannot coexist with an address record
	for _, record := range reconciliation.deletes {
		if _, err := self.call(http.MethodDelete, "/zones/"+reconciliation.zoneId+"/dns_records/"+record.Id, nil, nil); err != nil {
			return nil, err
		}
	}
	for _, record := range reconciliation.updates {
		body := &cloudflareRecord{Type: record.Type, Name: record.Name, Content: record.Content, Ttl: record.Ttl, Proxied: record.Proxied, Comment: record.Comment}
		if _, err := self.call(http.MethodPut, "/zones/"+reconciliation.zoneId+"/dns_records/"+record.Id, nil, body); err != nil {
			return nil, err
		}
	}
	for _, record := range reconciliation.creates {
		if _, err := self.call(http.MethodPost, "/zones/"+reconciliation.zoneId+"/dns_records", nil, record); err != nil {
			return nil, err
		}
	}
	return reconciliation.changes, nil
}
