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
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/mysql/armmysqlflexibleservers/v2"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeMySQLFlexibleServer = "AZURE::DBforMySQL::FlexibleServer"

// mySQLFlexibleServersAPI is the armmysqlflexibleservers surface used here. Note
// the asymmetry with PostgreSQL: MySQL's create verb is BeginCreate, not
// BeginCreateOrUpdate, so a create against an existing name is an error rather
// than an upsert.
type mySQLFlexibleServersAPI interface {
	BeginCreate(ctx context.Context, resourceGroupName string, serverName string, parameters armmysqlflexibleservers.Server, options *armmysqlflexibleservers.ServersClientBeginCreateOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientCreateResponse], error)
	Get(ctx context.Context, resourceGroupName string, serverName string, options *armmysqlflexibleservers.ServersClientGetOptions) (armmysqlflexibleservers.ServersClientGetResponse, error)
	BeginUpdate(ctx context.Context, resourceGroupName string, serverName string, parameters armmysqlflexibleservers.ServerForUpdate, options *armmysqlflexibleservers.ServersClientBeginUpdateOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientUpdateResponse], error)
	BeginDelete(ctx context.Context, resourceGroupName string, serverName string, options *armmysqlflexibleservers.ServersClientBeginDeleteOptions) (*runtime.Poller[armmysqlflexibleservers.ServersClientDeleteResponse], error)
	NewListPager(options *armmysqlflexibleservers.ServersClientListOptions) *runtime.Pager[armmysqlflexibleservers.ServersClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armmysqlflexibleservers.ServersClientListByResourceGroupOptions) *runtime.Pager[armmysqlflexibleservers.ServersClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeMySQLFlexibleServer, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &MySQLFlexibleServer{
			api:      c.MySQLFlexibleServersClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// MySQLFlexibleServer is the provisioner for Azure Database for MySQL flexible
// servers (Microsoft.DBforMySQL/flexibleServers).
//
// administratorLoginPassword is write-only: ARM never returns it, so it is never
// serialized back into state.
type MySQLFlexibleServer struct {
	api      mySQLFlexibleServersAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func mySQLFlexibleServerIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "flexibleservers")
	if err != nil {
		return "", "", err
	}
	return rgName, names["flexibleservers"], nil
}

func (m *MySQLFlexibleServer) buildPropertiesFromResult(server *armmysqlflexibleservers.Server, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if server.ID != nil {
		props["id"] = *server.ID
	}
	if server.Name != nil {
		props["name"] = *server.Name
	}
	if server.Location != nil {
		props["location"] = strings.ToLower(strings.ReplaceAll(*server.Location, " ", ""))
	}
	if sku := server.SKU; sku != nil {
		s := map[string]any{}
		if sku.Name != nil {
			s["name"] = *sku.Name
		}
		if sku.Tier != nil {
			s["tier"] = string(*sku.Tier)
		}
		if len(s) > 0 {
			props["sku"] = s
		}
	}

	if p := server.Properties; p != nil {
		if p.Version != nil {
			props["version"] = string(*p.Version)
		}
		// The login is safe to surface; the password is not and ARM never returns it.
		if p.AdministratorLogin != nil {
			props["administratorLogin"] = *p.AdministratorLogin
		}
		if p.AvailabilityZone != nil {
			props["availabilityZone"] = *p.AvailabilityZone
		}
		if p.FullyQualifiedDomainName != nil {
			props["fullyQualifiedDomainName"] = *p.FullyQualifiedDomainName
		}
		if p.State != nil {
			props["state"] = string(*p.State)
		}

		if st := p.Storage; st != nil {
			s := map[string]any{}
			if st.StorageSizeGB != nil {
				s["storageSizeGB"] = *st.StorageSizeGB
			}
			if st.Iops != nil {
				s["iops"] = *st.Iops
			}
			if st.AutoGrow != nil {
				s["autoGrow"] = string(*st.AutoGrow)
			}
			if len(s) > 0 {
				props["storage"] = s
			}
		}
		if b := p.Backup; b != nil {
			s := map[string]any{}
			if b.BackupRetentionDays != nil {
				s["backupRetentionDays"] = *b.BackupRetentionDays
			}
			if b.GeoRedundantBackup != nil {
				s["geoRedundantBackup"] = string(*b.GeoRedundantBackup)
			}
			if len(s) > 0 {
				props["backup"] = s
			}
		}
		if ha := p.HighAvailability; ha != nil {
			s := map[string]any{}
			if ha.Mode != nil {
				s["mode"] = string(*ha.Mode)
			}
			if ha.StandbyAvailabilityZone != nil {
				s["standbyAvailabilityZone"] = *ha.StandbyAvailabilityZone
			}
			if len(s) > 0 {
				props["highAvailability"] = s
			}
		}
		if n := p.Network; n != nil {
			s := map[string]any{}
			if n.PublicNetworkAccess != nil {
				s["publicNetworkAccess"] = string(*n.PublicNetworkAccess)
			}
			if n.DelegatedSubnetResourceID != nil {
				s["delegatedSubnetResourceId"] = *n.DelegatedSubnetResourceID
			}
			if n.PrivateDNSZoneResourceID != nil {
				s["privateDnsZoneResourceId"] = *n.PrivateDNSZoneResourceID
			}
			if len(s) > 0 {
				props["network"] = s
			}
		}
	}

	if tags := azureTagsToFormaeTags(server.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func mySQLStorageFromProps(props map[string]any) *armmysqlflexibleservers.Storage {
	raw, ok := props["storage"].(map[string]any)
	if !ok {
		return nil
	}
	st := &armmysqlflexibleservers.Storage{}
	if v, ok := capacity(raw["storageSizeGB"]); ok {
		st.StorageSizeGB = to.Ptr(v)
	}
	if v, ok := capacity(raw["iops"]); ok {
		st.Iops = to.Ptr(v)
	}
	if v, ok := raw["autoGrow"].(string); ok && v != "" {
		st.AutoGrow = to.Ptr(armmysqlflexibleservers.EnableStatusEnum(v))
	}
	return st
}

func mySQLBackupFromProps(props map[string]any) *armmysqlflexibleservers.Backup {
	raw, ok := props["backup"].(map[string]any)
	if !ok {
		return nil
	}
	b := &armmysqlflexibleservers.Backup{}
	if v, ok := capacity(raw["backupRetentionDays"]); ok {
		b.BackupRetentionDays = to.Ptr(v)
	}
	if v, ok := raw["geoRedundantBackup"].(string); ok && v != "" {
		b.GeoRedundantBackup = to.Ptr(armmysqlflexibleservers.EnableStatusEnum(v))
	}
	return b
}

func mySQLHighAvailabilityFromProps(props map[string]any) *armmysqlflexibleservers.HighAvailability {
	raw, ok := props["highAvailability"].(map[string]any)
	if !ok {
		return nil
	}
	ha := &armmysqlflexibleservers.HighAvailability{}
	if v, ok := raw["mode"].(string); ok && v != "" {
		ha.Mode = to.Ptr(armmysqlflexibleservers.HighAvailabilityMode(v))
	}
	if v, ok := raw["standbyAvailabilityZone"].(string); ok && v != "" {
		ha.StandbyAvailabilityZone = to.Ptr(v)
	}
	return ha
}

func mySQLNetworkFromProps(props map[string]any) *armmysqlflexibleservers.Network {
	raw, ok := props["network"].(map[string]any)
	if !ok {
		return nil
	}
	n := &armmysqlflexibleservers.Network{}
	if v, ok := raw["publicNetworkAccess"].(string); ok && v != "" {
		n.PublicNetworkAccess = to.Ptr(armmysqlflexibleservers.EnableStatusEnum(v))
	}
	if v, ok := raw["delegatedSubnetResourceId"].(string); ok && v != "" {
		n.DelegatedSubnetResourceID = to.Ptr(v)
	}
	if v, ok := raw["privateDnsZoneResourceId"].(string); ok && v != "" {
		n.PrivateDNSZoneResourceID = to.Ptr(v)
	}
	return n
}

func mySQLSKUFromProps(props map[string]any) *armmysqlflexibleservers.MySQLServerSKU {
	raw, ok := props["sku"].(map[string]any)
	if !ok {
		return nil
	}
	name, _ := raw["name"].(string)
	tier, _ := raw["tier"].(string)
	if name == "" || tier == "" {
		return nil
	}
	return &armmysqlflexibleservers.MySQLServerSKU{
		Name: to.Ptr(name),
		Tier: to.Ptr(armmysqlflexibleservers.ServerSKUTier(tier)),
	}
}

func (m *MySQLFlexibleServer) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	location, _ := props["location"].(string)
	if location == "" {
		return nil, fmt.Errorf("location is required")
	}
	adminLogin, _ := props["administratorLogin"].(string)
	if adminLogin == "" {
		return nil, fmt.Errorf("administratorLogin is required")
	}
	adminPassword, _ := props["administratorLoginPassword"].(string)
	if adminPassword == "" {
		return nil, fmt.Errorf("administratorLoginPassword is required")
	}
	version, _ := props["version"].(string)
	if version == "" {
		return nil, fmt.Errorf("version is required")
	}
	sku := mySQLSKUFromProps(props)
	if sku == nil {
		return nil, fmt.Errorf("sku.name and sku.tier are required")
	}
	name, _ := props["name"].(string)
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	serverProps := &armmysqlflexibleservers.ServerProperties{
		AdministratorLogin:         to.Ptr(adminLogin),
		AdministratorLoginPassword: to.Ptr(adminPassword),
		Version:                    to.Ptr(armmysqlflexibleservers.ServerVersion(version)),
		Storage:                    mySQLStorageFromProps(props),
		Backup:                     mySQLBackupFromProps(props),
		HighAvailability:           mySQLHighAvailabilityFromProps(props),
		Network:                    mySQLNetworkFromProps(props),
	}
	if v, ok := props["availabilityZone"].(string); ok && v != "" {
		serverProps.AvailabilityZone = to.Ptr(v)
	}

	params := armmysqlflexibleservers.Server{
		Location:   to.Ptr(location),
		SKU:        sku,
		Properties: serverProps,
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := m.api.BeginCreate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforMySQL/flexibleServers/%s",
		m.config.SubscriptionId, rgName, name)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       operationErrorCode(err),
				},
			}, nil
		}
		propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.Server, rgName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpCreate, resumeToken, expectedNativeID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (m *MySQLFlexibleServer) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := mySQLFlexibleServerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := m.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.Server, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeMySQLFlexibleServer,
		Properties:   string(propsJSON),
	}, nil
}

// Update patches the in-place subset. version, administratorLogin, the password
// and availabilityZone are createOnly in the schema, so they never reach here.
func (m *MySQLFlexibleServer) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := mySQLFlexibleServerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params := armmysqlflexibleservers.ServerForUpdate{
		Properties: &armmysqlflexibleservers.ServerPropertiesForUpdate{
			Storage:          mySQLStorageFromProps(props),
			Backup:           mySQLBackupFromProps(props),
			HighAvailability: mySQLHighAvailabilityFromProps(props),
			Network:          mySQLNetworkFromProps(props),
		},
	}
	if sku := mySQLSKUFromProps(props); sku != nil {
		params.SKU = sku
	}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	poller, err := m.api.BeginUpdate(ctx, rgName, name, params, nil)
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

	if poller.Done() {
		result, err := poller.Result(ctx)
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
		propsJSON, err := json.Marshal(m.buildPropertiesFromResult(&result.Server, rgName))
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           request.NativeID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpUpdate, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (m *MySQLFlexibleServer) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := mySQLFlexibleServerIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := m.api.BeginDelete(ctx, rgName, name, nil)
	if err != nil {
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

	if poller.Done() {
		if _, err := poller.Result(ctx); err != nil && !isDeleteSuccessError(err) {
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqIDJSON, err := encodeLROStart(lroOpDelete, resumeToken, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqIDJSON,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (m *MySQLFlexibleServer) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return nil, err
	}

	switch reqID.OperationType {
	case lroOpCreate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armmysqlflexibleservers.ServersClientCreateResponse], error) {
				return resumePoller[armmysqlflexibleservers.ServersClientCreateResponse](m.pipeline, token)
			},
			func(_ context.Context, result armmysqlflexibleservers.ServersClientCreateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return m.completeFromServer(&result.Server)
			})
	case lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationUpdate,
			func(token string) (*runtime.Poller[armmysqlflexibleservers.ServersClientUpdateResponse], error) {
				return resumePoller[armmysqlflexibleservers.ServersClientUpdateResponse](m.pipeline, token)
			},
			func(_ context.Context, result armmysqlflexibleservers.ServersClientUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				return m.completeFromServer(&result.Server)
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armmysqlflexibleservers.ServersClientDeleteResponse], error) {
				return resumePoller[armmysqlflexibleservers.ServersClientDeleteResponse](m.pipeline, token)
			}, nil)
	default:
		return nil, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (m *MySQLFlexibleServer) completeFromServer(server *armmysqlflexibleservers.Server) (string, json.RawMessage, error) {
	nativeID := ""
	rgName := ""
	if server.ID != nil {
		nativeID = *server.ID
		if rg, _, err := mySQLFlexibleServerIDParts(*server.ID); err == nil {
			rgName = rg
		}
	}
	propsJSON, err := json.Marshal(m.buildPropertiesFromResult(server, rgName))
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return nativeID, propsJSON, nil
}

func (m *MySQLFlexibleServer) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := m.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list mysql flexible servers: %w", err)
			}
			for _, server := range page.Value {
				if server.ID != nil {
					nativeIDs = append(nativeIDs, *server.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := m.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list mysql flexible servers: %w", err)
		}
		for _, server := range page.Value {
			if server.ID != nil {
				nativeIDs = append(nativeIDs, *server.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
