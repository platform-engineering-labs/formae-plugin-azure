// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDnsRecordSet = "AZURE::Network::DnsRecordSet"

// recordSetsAPI is the narrow slice of *armdns.RecordSetsClient used by the
// provisioner. All record-set operations (CreateOrUpdate, Get, Delete) are
// synchronous — there is no LRO, so Status simply re-reads the resource.
type recordSetsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, recordType armdns.RecordType, parameters armdns.RecordSet, options *armdns.RecordSetsClientCreateOrUpdateOptions) (armdns.RecordSetsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientGetOptions) (armdns.RecordSetsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, recordType armdns.RecordType, options *armdns.RecordSetsClientDeleteOptions) (armdns.RecordSetsClientDeleteResponse, error)
	NewListByDNSZonePager(resourceGroupName string, zoneName string, options *armdns.RecordSetsClientListByDNSZoneOptions) *runtime.Pager[armdns.RecordSetsClientListByDNSZoneResponse]
}

func init() {
	registry.Register(ResourceTypeDnsRecordSet, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DnsRecordSet{
			api:    c.RecordSetsClient,
			config: cfg,
		}
	})
}

// DnsRecordSet is the provisioner for Azure public DNS record sets. A single
// polymorphic resource models A, CNAME and TXT record sets, discriminated by
// the createOnly `recordType` field. armdns keeps the typed record arrays in
// distinct fields (ARecords / CnameRecord / TxtRecords) that never collide, so
// the discriminator stays clean and round-trips without drift.
type DnsRecordSet struct {
	api    recordSetsAPI
	config *config.Config
}

// buildRecordSetParams converts the formae property map into an armdns.RecordSet
// body plus the record type used as the API path segment. Shared by Create and
// Update so the request shape is identical.
func buildRecordSetParams(props map[string]any) (armdns.RecordSet, armdns.RecordType, error) {
	rtStr, _ := props["recordType"].(string)
	if rtStr == "" {
		return armdns.RecordSet{}, "", fmt.Errorf("recordType is required")
	}
	recordType := armdns.RecordType(strings.ToUpper(rtStr))

	rsProps := &armdns.RecordSetProperties{}
	if ttl, ok := props["ttl"].(float64); ok {
		v := int64(ttl)
		rsProps.TTL = &v
	}

	switch recordType {
	case armdns.RecordTypeA:
		records, err := aRecordsFromProperties(props["aRecords"])
		if err != nil {
			return armdns.RecordSet{}, "", err
		}
		rsProps.ARecords = records
	case armdns.RecordTypeCNAME:
		cname, ok := props["cname"].(string)
		if !ok || cname == "" {
			return armdns.RecordSet{}, "", fmt.Errorf("cname is required for CNAME record sets")
		}
		rsProps.CnameRecord = &armdns.CnameRecord{Cname: stringPtr(cname)}
	case armdns.RecordTypeTXT:
		records, err := txtRecordsFromProperties(props["txtRecords"])
		if err != nil {
			return armdns.RecordSet{}, "", err
		}
		rsProps.TxtRecords = records
	default:
		return armdns.RecordSet{}, "", fmt.Errorf("unsupported recordType: %s", rtStr)
	}

	return armdns.RecordSet{Properties: rsProps}, recordType, nil
}

func aRecordsFromProperties(raw any) ([]*armdns.ARecord, error) {
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("aRecords is required for A record sets")
	}
	records := make([]*armdns.ARecord, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("aRecords[%d] must be an object", i)
		}
		ip, ok := m["ipv4Address"].(string)
		if !ok || ip == "" {
			return nil, fmt.Errorf("aRecords[%d].ipv4Address is required", i)
		}
		records = append(records, &armdns.ARecord{IPv4Address: stringPtr(ip)})
	}
	return records, nil
}

func txtRecordsFromProperties(raw any) ([]*armdns.TxtRecord, error) {
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("txtRecords is required for TXT record sets")
	}
	records := make([]*armdns.TxtRecord, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("txtRecords[%d] must be an object", i)
		}
		valuesRaw, ok := m["value"].([]any)
		if !ok || len(valuesRaw) == 0 {
			return nil, fmt.Errorf("txtRecords[%d].value is required", i)
		}
		values := make([]*string, 0, len(valuesRaw))
		for j, v := range valuesRaw {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("txtRecords[%d].value[%d] must be a string", i, j)
			}
			values = append(values, stringPtr(s))
		}
		records = append(records, &armdns.TxtRecord{Value: values})
	}
	return records, nil
}

func serializeDnsRecordSetProperties(result armdns.RecordSet, rgName, zoneName, recordType, relativeName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["zoneName"] = zoneName
	props["recordType"] = strings.ToUpper(recordType)
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = relativeName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if result.Properties != nil {
		p := result.Properties
		if p.TTL != nil {
			props["ttl"] = *p.TTL
		}
		if p.Fqdn != nil {
			props["fqdn"] = *p.Fqdn
		}
		switch armdns.RecordType(props["recordType"].(string)) {
		case armdns.RecordTypeA:
			if len(p.ARecords) > 0 {
				aRecords := make([]map[string]any, 0, len(p.ARecords))
				for _, r := range p.ARecords {
					if r != nil && r.IPv4Address != nil {
						aRecords = append(aRecords, map[string]any{"ipv4Address": *r.IPv4Address})
					}
				}
				props["aRecords"] = aRecords
			}
		case armdns.RecordTypeCNAME:
			if p.CnameRecord != nil && p.CnameRecord.Cname != nil {
				props["cname"] = *p.CnameRecord.Cname
			}
		case armdns.RecordTypeTXT:
			if len(p.TxtRecords) > 0 {
				txtRecords := make([]map[string]any, 0, len(p.TxtRecords))
				for _, r := range p.TxtRecords {
					if r == nil {
						continue
					}
					values := make([]string, 0, len(r.Value))
					for _, v := range r.Value {
						if v != nil {
							values = append(values, *v)
						}
					}
					txtRecords = append(txtRecords, map[string]any{"value": values})
				}
				props["txtRecords"] = txtRecords
			}
		}
	}

	return json.Marshal(props)
}

func recordSetIdentity(props map[string]any) (rgName, zoneName, relativeName string, err error) {
	rgName, _ = props["resourceGroupName"].(string)
	if rgName == "" {
		return "", "", "", fmt.Errorf("resourceGroupName is required")
	}
	zoneName, _ = props["zoneName"].(string)
	if zoneName == "" {
		return "", "", "", fmt.Errorf("zoneName is required")
	}
	relativeName, _ = props["name"].(string)
	if relativeName == "" {
		return "", "", "", fmt.Errorf("name is required")
	}
	return rgName, zoneName, relativeName, nil
}

func (r *DnsRecordSet) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	rgName, zoneName, relativeName, err := recordSetIdentity(props)
	if err != nil {
		return nil, err
	}

	params, recordType, err := buildRecordSetParams(props)
	if err != nil {
		return nil, err
	}

	result, err := r.api.CreateOrUpdate(ctx, rgName, zoneName, relativeName, recordType, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeDnsRecordSetProperties(result.RecordSet, rgName, zoneName, string(recordType), relativeName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DnsRecordSet properties: %w", err)
	}
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (r *DnsRecordSet) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, zoneName, recordType, relativeName, err := dnsRecordSetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}
	result, err := r.api.Get(ctx, rgName, zoneName, relativeName, armdns.RecordType(recordType), nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}
	propsJSON, err := serializeDnsRecordSetProperties(result.RecordSet, rgName, zoneName, recordType, relativeName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DnsRecordSet properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDnsRecordSet,
		Properties:   string(propsJSON),
	}, nil
}

func (r *DnsRecordSet) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, zoneName, recordType, relativeName, err := dnsRecordSetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params, _, err := buildRecordSetParams(props)
	if err != nil {
		return nil, err
	}

	result, err := r.api.CreateOrUpdate(ctx, rgName, zoneName, relativeName, armdns.RecordType(recordType), params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializeDnsRecordSetProperties(result.RecordSet, rgName, zoneName, recordType, relativeName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DnsRecordSet properties: %w", err)
	}
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (r *DnsRecordSet) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, zoneName, recordType, relativeName, err := dnsRecordSetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := r.api.Delete(ctx, rgName, zoneName, relativeName, armdns.RecordType(recordType), nil); err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to delete DnsRecordSet: %w", err)
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (r *DnsRecordSet) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	// All record-set operations are synchronous, so Status is only reached for
	// a straight read-back confirmation.
	rgName, zoneName, recordType, relativeName, err := dnsRecordSetIDParts(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	result, err := r.api.Get(ctx, rgName, zoneName, relativeName, armdns.RecordType(recordType), nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to get DnsRecordSet status: %w", err)
	}

	propsJSON, err := serializeDnsRecordSetProperties(result.RecordSet, rgName, zoneName, recordType, relativeName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize DnsRecordSet properties: %w", err)
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (r *DnsRecordSet) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	zoneName := request.AdditionalProperties["zoneName"]
	if rgName == "" || zoneName == "" {
		return &resource.ListResult{}, nil
	}
	var nativeIDs []string
	pager := r.api.NewListByDNSZonePager(rgName, zoneName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list dns record sets: %w", err)
		}
		for _, x := range page.Value {
			if x != nil && x.ID != nil {
				nativeIDs = append(nativeIDs, *x.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

// dnsRecordSetIDParts extracts the resource group, zone name, record type and
// relative record set name from a record-set ARM ID of the form
// .../providers/Microsoft.Network/dnszones/<zone>/<TYPE>/<relativeName>.
//
// The record TYPE (A / CNAME / TXT) is a path segment, not a named ARM
// resource, so it is read from the leaf resource type's last segment rather
// than via armNameByType.
func dnsRecordSetIDParts(resourceID string) (rgName, zoneName, recordType, relativeName string, err error) {
	id, err := parseARMResourceID(resourceID)
	if err != nil {
		return "", "", "", "", err
	}
	rgName, err = armResourceGroup(id, resourceID)
	if err != nil {
		return "", "", "", "", err
	}
	if id.Name == "" {
		return "", "", "", "", fmt.Errorf("ARM ID missing record set name: %s", resourceID)
	}
	relativeName = id.Name
	types := id.ResourceType.Types
	if len(types) == 0 {
		return "", "", "", "", fmt.Errorf("ARM ID missing record type: %s", resourceID)
	}
	recordType = strings.ToUpper(types[len(types)-1])
	zone, ok := armNameByType(id, "dnszones")
	if !ok {
		return "", "", "", "", fmt.Errorf("ARM ID missing dnszones: %s", resourceID)
	}
	zoneName = zone
	return rgName, zoneName, recordType, relativeName, nil
}
