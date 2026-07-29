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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypePrivateDnsRecordSet = "AZURE::Network::PrivateDnsRecordSet"

// privateDnsSOARecordType is the SOA record set Azure creates automatically with
// every private zone. It cannot be deleted, so List must not surface it.
const privateDnsSOARecordType = "SOA"

// privateDnsRecordSetsAPI is the narrow slice of *armprivatedns.RecordSetsClient
// used here. Record set operations are synchronous (no LRO/poller).
//
// Careful: the parameter order differs from the public DNS client. armprivatedns
// takes (rg, zone, recordType, relativeName, ...) while armdns takes
// (rg, zone, relativeName, recordType, ...) — both are (string, string, X, Y) so
// swapping them still compiles.
type privateDnsRecordSetsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, privateZoneName string, recordType armprivatedns.RecordType, relativeRecordSetName string, parameters armprivatedns.RecordSet, options *armprivatedns.RecordSetsClientCreateOrUpdateOptions) (armprivatedns.RecordSetsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, privateZoneName string, recordType armprivatedns.RecordType, relativeRecordSetName string, options *armprivatedns.RecordSetsClientGetOptions) (armprivatedns.RecordSetsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, privateZoneName string, recordType armprivatedns.RecordType, relativeRecordSetName string, options *armprivatedns.RecordSetsClientDeleteOptions) (armprivatedns.RecordSetsClientDeleteResponse, error)
	NewListPager(resourceGroupName string, privateZoneName string, options *armprivatedns.RecordSetsClientListOptions) *runtime.Pager[armprivatedns.RecordSetsClientListResponse]
}

func init() {
	registry.Register(ResourceTypePrivateDnsRecordSet, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &PrivateDnsRecordSet{api: c.PrivateDnsRecordSetsClient, config: cfg}
	})
}

// PrivateDnsRecordSet is the provisioner for record sets inside an Azure private
// DNS zone (`Microsoft.Network/privateDnsZones/<zone>/<TYPE>/<name>`). It is a
// child of AZURE::Network::PrivateDnsZone. All operations are synchronous.
//
// Record type coverage matches the public dnsrecordset.go sibling: A, CNAME and
// TXT. Private zones additionally support AAAA, MX, PTR and SRV; those are deferred
// so the two record-set types stay in step rather than diverging.
type PrivateDnsRecordSet struct {
	api    privateDnsRecordSetsAPI
	config *config.Config
}

// privateDnsRecordSetIDParts extracts resource group, zone, record type and
// relative name from an ID of the form
// .../providers/Microsoft.Network/privateDnsZones/<zone>/<TYPE>/<relativeName>.
//
// The record TYPE is a path segment rather than a named ARM resource, so it is read
// off the leaf resource type instead of via armNameByType — same approach as
// dnsRecordSetIDParts.
func privateDnsRecordSetIDParts(resourceID string) (rgName, zoneName, recordType, relativeName string, err error) {
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
	zone, ok := armNameByType(id, "privatednszones")
	if !ok {
		return "", "", "", "", fmt.Errorf("ARM ID missing privateDnsZones: %s", resourceID)
	}
	return rgName, zone, recordType, relativeName, nil
}

func buildPrivateDnsRecordSetParams(props map[string]any) (armprivatedns.RecordSet, armprivatedns.RecordType, error) {
	rtStr, _ := props["recordType"].(string)
	if rtStr == "" {
		return armprivatedns.RecordSet{}, "", fmt.Errorf("recordType is required")
	}
	recordType := armprivatedns.RecordType(strings.ToUpper(rtStr))

	rsProps := &armprivatedns.RecordSetProperties{}
	if ttl, ok := props["ttl"].(float64); ok {
		v := int64(ttl)
		rsProps.TTL = &v
	}

	switch recordType {
	case armprivatedns.RecordTypeA:
		records, err := privateDnsARecordsFromProperties(props["aRecords"])
		if err != nil {
			return armprivatedns.RecordSet{}, "", err
		}
		rsProps.ARecords = records
	case armprivatedns.RecordTypeCNAME:
		cname, ok := props["cname"].(string)
		if !ok || cname == "" {
			return armprivatedns.RecordSet{}, "", fmt.Errorf("cname is required for CNAME record sets")
		}
		rsProps.CnameRecord = &armprivatedns.CnameRecord{Cname: stringPtr(cname)}
	case armprivatedns.RecordTypeTXT:
		records, err := privateDnsTxtRecordsFromProperties(props["txtRecords"])
		if err != nil {
			return armprivatedns.RecordSet{}, "", err
		}
		rsProps.TxtRecords = records
	default:
		return armprivatedns.RecordSet{}, "", fmt.Errorf("unsupported recordType: %s", rtStr)
	}

	return armprivatedns.RecordSet{Properties: rsProps}, recordType, nil
}

func privateDnsARecordsFromProperties(raw any) ([]*armprivatedns.ARecord, error) {
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("aRecords is required for A record sets")
	}
	records := make([]*armprivatedns.ARecord, 0, len(list))
	for i, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("aRecords[%d] must be an object", i)
		}
		ip, ok := m["ipv4Address"].(string)
		if !ok || ip == "" {
			return nil, fmt.Errorf("aRecords[%d].ipv4Address is required", i)
		}
		records = append(records, &armprivatedns.ARecord{IPv4Address: stringPtr(ip)})
	}
	return records, nil
}

func privateDnsTxtRecordsFromProperties(raw any) ([]*armprivatedns.TxtRecord, error) {
	list, ok := raw.([]any)
	if !ok || len(list) == 0 {
		return nil, fmt.Errorf("txtRecords is required for TXT record sets")
	}
	records := make([]*armprivatedns.TxtRecord, 0, len(list))
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
		for _, v := range valuesRaw {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("txtRecords[%d].value entries must be strings", i)
			}
			values = append(values, stringPtr(s))
		}
		records = append(records, &armprivatedns.TxtRecord{Value: values})
	}
	return records, nil
}

func serializePrivateDnsRecordSetProperties(result armprivatedns.RecordSet, rgName, zoneName, recordType, relativeName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["privateZoneName"] = zoneName
	props["recordType"] = recordType
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = relativeName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}

	if p := result.Properties; p != nil {
		if p.TTL != nil {
			props["ttl"] = int(*p.TTL)
		}
		if len(p.ARecords) > 0 {
			records := make([]map[string]any, 0, len(p.ARecords))
			for _, r := range p.ARecords {
				if r != nil && r.IPv4Address != nil {
					records = append(records, map[string]any{"ipv4Address": *r.IPv4Address})
				}
			}
			if len(records) > 0 {
				props["aRecords"] = records
			}
		}
		if p.CnameRecord != nil && p.CnameRecord.Cname != nil {
			props["cname"] = *p.CnameRecord.Cname
		}
		if len(p.TxtRecords) > 0 {
			records := make([]map[string]any, 0, len(p.TxtRecords))
			for _, r := range p.TxtRecords {
				if r == nil || len(r.Value) == 0 {
					continue
				}
				values := make([]string, 0, len(r.Value))
				for _, v := range r.Value {
					if v != nil {
						values = append(values, *v)
					}
				}
				if len(values) > 0 {
					records = append(records, map[string]any{"value": values})
				}
			}
			if len(records) > 0 {
				props["txtRecords"] = records
			}
		}
	}

	return json.Marshal(props)
}

func (r *PrivateDnsRecordSet) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	zoneName, _ := props["privateZoneName"].(string)
	if zoneName == "" {
		return nil, fmt.Errorf("privateZoneName is required")
	}
	relativeName, _ := props["name"].(string)
	if relativeName == "" {
		relativeName = request.Label
	}
	if relativeName == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, recordType, err := buildPrivateDnsRecordSetParams(props)
	if err != nil {
		return nil, err
	}

	result, err := r.api.CreateOrUpdate(ctx, rgName, zoneName, recordType, relativeName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := serializePrivateDnsRecordSetProperties(result.RecordSet, rgName, zoneName, string(recordType), relativeName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PrivateDnsRecordSet properties: %w", err)
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (r *PrivateDnsRecordSet) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, zoneName, recordType, relativeName, err := privateDnsRecordSetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := r.api.Get(ctx, rgName, zoneName, armprivatedns.RecordType(recordType), relativeName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializePrivateDnsRecordSetProperties(result.RecordSet, rgName, zoneName, recordType, relativeName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PrivateDnsRecordSet properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypePrivateDnsRecordSet,
		Properties:   string(propsJSON),
	}, nil
}

func (r *PrivateDnsRecordSet) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, zoneName, recordType, relativeName, err := privateDnsRecordSetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse desired properties: %w", err)
	}
	// The record type is fixed by the native ID; it is createOnly in the schema, so
	// take it from the ID rather than trusting the payload.
	props["recordType"] = recordType

	params, parsedType, err := buildPrivateDnsRecordSetParams(props)
	if err != nil {
		return nil, err
	}

	result, err := r.api.CreateOrUpdate(ctx, rgName, zoneName, parsedType, relativeName, params, nil)
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

	propsJSON, err := serializePrivateDnsRecordSetProperties(result.RecordSet, rgName, zoneName, recordType, relativeName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize PrivateDnsRecordSet properties: %w", err)
	}

	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (r *PrivateDnsRecordSet) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, zoneName, recordType, relativeName, err := privateDnsRecordSetIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	// Synchronous delete. NotFound means the goal is already achieved.
	if _, err := r.api.Delete(ctx, rgName, zoneName, armprivatedns.RecordType(recordType), relativeName, nil); err != nil {
		if isDeleteSuccessError(err) {
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
		}, nil
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

// Status is a no-op success passthrough: private DNS record set operations are
// synchronous, so Create/Update/Delete never return InProgress. It exists only to
// satisfy the Provisioner interface.
func (r *PrivateDnsRecordSet) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (r *PrivateDnsRecordSet) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	zoneName := request.AdditionalProperties["privateZoneName"]

	var nativeIDs []string
	pager := r.api.NewListPager(rgName, zoneName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list private DNS record sets in zone %s: %w", zoneName, err)
		}
		for _, rs := range page.Value {
			if rs.ID == nil {
				continue
			}
			// Azure creates an SOA record set with every private zone and refuses to
			// delete it — never surface it as a manageable resource.
			if rs.Type != nil && strings.HasSuffix(strings.ToUpper(*rs.Type), "/"+privateDnsSOARecordType) {
				continue
			}
			nativeIDs = append(nativeIDs, *rs.ID)
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
