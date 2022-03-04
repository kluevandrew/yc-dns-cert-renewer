package yandex

import (
	"context"
	"fmt"
	"github.com/go-acme/lego/challenge/dns01"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/dns/v1"
	"github.com/yandex-cloud/go-genproto/yandex/cloud/operation"
	ycsdk "github.com/yandex-cloud/go-sdk"
	"time"
)

const (
	DefaultPropagationTimeout = 120 * time.Second
	DefaultTTL                = 60
	dnsTemplate               = `%s %d IN TXT "%s"`
)

type DNSProvider struct {
	SDK      *ycsdk.SDK
	FolderID string
	Context  context.Context
}

func NewDNSProvider(ctx context.Context, creds ycsdk.Credentials, folderID string) (*DNSProvider, error) {
	sdk, err := ycsdk.Build(ctx, ycsdk.Config{
		Credentials: creds,
	})
	if err != nil {
		return nil, err
	}

	return &DNSProvider{
		Context:  ctx,
		SDK:      sdk,
		FolderID: folderID,
	}, nil
}

func (p *DNSProvider) GetZones() ([]*dns.DnsZone, error) {
	request := &dns.ListDnsZonesRequest{
		FolderId: p.FolderID,
	}

	response, err := p.SDK.DNS().DnsZone().List(p.Context, request)
	if err != nil {
		return nil, err
	}

	return response.DnsZones, nil
}

func (p *DNSProvider) Present(domain, token, keyAuth string) error {
	fqdn, value := dns01.GetRecord(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		return err
	}

	ycZones, err := p.GetZones()
	if err != nil {
		return err
	}

	var ycZoneID string

	for _, zone := range ycZones {
		if zone.GetZone() == authZone {
			ycZoneID = zone.GetId()
		}
	}

	if ycZoneID == "" {
		return fmt.Errorf("cant find dns zone %s in yandex cloud", authZone)
	}

	fmt.Printf("The following TXT record will be added into your %s zone:\n", authZone)
	fmt.Printf(dnsTemplate+"\n", fqdn, DefaultTTL, value)
	name := fqdn[:len(fqdn)-len(authZone)-1]

	record, err := p.createOrUpdateRecord(ycZoneID, name, value)
	if err != nil {
		return err
	}

	fmt.Printf("yandex cloud dns record id is %s\n", record.Id)

	return err
}

func (p *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	fqdn, _ := dns01.GetRecord(domain, keyAuth)

	authZone, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		return err
	}

	ycZones, err := p.GetZones()
	if err != nil {
		return err
	}

	var ycZoneID string

	for _, zone := range ycZones {
		if zone.GetZone() == authZone {
			ycZoneID = zone.GetId()
		}
	}

	if ycZoneID == "" {
		fmt.Printf("cant find dns zone %s in yandex cloud\n", authZone)
		return nil
	}

	fmt.Printf("The following TXT record will be removed from your %s zone:\n", authZone)
	fmt.Printf(dnsTemplate+"\n", fqdn, DefaultTTL, "...")
	name := fqdn[:len(fqdn)-len(authZone)-1]

	_, err = p.removeRecord(ycZoneID, name)
	if err != nil {
		return err
	}

	return nil
}

func (p *DNSProvider) createOrUpdateRecord(zoneID string, name string, value string) (*operation.Operation, error) {
	get := &dns.GetDnsZoneRecordSetRequest{
		DnsZoneId: zoneID,
		Name:      name,
		Type:      "TXT",
	}

	exists, _ := p.SDK.DNS().DnsZone().GetRecordSet(p.Context, get)

	var deletions []*dns.RecordSet
	if exists != nil {
		deletions = append(deletions, exists)
	}

	update := &dns.UpdateRecordSetsRequest{
		DnsZoneId: zoneID,
		Deletions: deletions,
		Additions: []*dns.RecordSet{
			{
				Name: name,
				Type: "TXT",
				Ttl:  DefaultTTL,
				Data: []string{
					value,
				},
			},
		},
	}

	return p.SDK.DNS().DnsZone().UpdateRecordSets(p.Context, update)
}

func (p *DNSProvider) removeRecord(zoneID string, name string) (*operation.Operation, error) {
	get := &dns.GetDnsZoneRecordSetRequest{
		DnsZoneId: zoneID,
		Name:      name,
		Type:      "TXT",
	}

	exists, _ := p.SDK.DNS().DnsZone().GetRecordSet(p.Context, get)

	var deletions []*dns.RecordSet
	if exists != nil {
		deletions = append(deletions, exists)
	}

	update := &dns.UpdateRecordSetsRequest{
		DnsZoneId: zoneID,
		Deletions: deletions,
		Additions: []*dns.RecordSet{},
	}

	return p.SDK.DNS().DnsZone().UpdateRecordSets(p.Context, update)
}

// Sequential All DNS challenges for this provider will be resolved sequentially.
// Returns the interval between each iteration.
func (p *DNSProvider) Sequential() time.Duration {
	return DefaultPropagationTimeout
}
