// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeSQLServerDNSAlias = "AZURE::Sql::ServerDnsAlias"

// sqlServerDNSAliasesAPI is the subset of *armsql.ServerDNSAliasesClient used here.
// Create/delete are LROs. Note BeginCreateOrUpdate takes **no request body** — an
// alias is just a name pointing at its parent server.
type sqlServerDNSAliasesAPI interface {
	BeginCreateOrUpdate(ctx context.Context, resourceGroupName, serverName, dnsAliasName string, options *armsql.ServerDNSAliasesClientBeginCreateOrUpdateOptions) (*runtime.Poller[armsql.ServerDNSAliasesClientCreateOrUpdateResponse], error)
	Get(ctx context.Context, resourceGroupName, serverName, dnsAliasName string, options *armsql.ServerDNSAliasesClientGetOptions) (armsql.ServerDNSAliasesClientGetResponse, error)
	BeginDelete(ctx context.Context, resourceGroupName, serverName, dnsAliasName string, options *armsql.ServerDNSAliasesClientBeginDeleteOptions) (*runtime.Poller[armsql.ServerDNSAliasesClientDeleteResponse], error)
	NewListByServerPager(resourceGroupName, serverName string, options *armsql.ServerDNSAliasesClientListByServerOptions) *runtime.Pager[armsql.ServerDNSAliasesClientListByServerResponse]
}

func init() {
	registry.Register(ResourceTypeSQLServerDNSAlias, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &SqlServerDnsAlias{
			api:      c.SQLServerDNSAliasesClient,
			pipeline: c.Pipeline(),
			config:   cfg,
		}
	})
}

// SqlServerDnsAlias is the provisioner for Azure SQL server DNS aliases
// (`Microsoft.Sql/servers/<server>/dnsAliases/<name>`) — a stable hostname that can
// be repointed between servers, so clients keep one connection string across a
// failover or migration.
//
// The alias has no writable properties: its only field, azureDnsRecord, is
// read-only, so Update is a re-read. Repointing an alias at a different server is
// the separate ARM `acquire` operation, which this plugin does not expose — see the
// note on Update.
type SqlServerDnsAlias struct {
	api      sqlServerDNSAliasesAPI
	pipeline runtime.Pipeline
	config   *config.Config
}

func sqlServerDNSAliasIDParts(resourceID string) (rgName, serverName, aliasName string, err error) {
	rgName, names, err := armIDParts(resourceID, "servers", "dnsaliases")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["servers"], names["dnsaliases"], nil
}

func serializeSQLServerDNSAliasProperties(result armsql.ServerDNSAlias, rgName, serverName, aliasName string) (json.RawMessage, error) {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName
	props["serverName"] = serverName
	if result.Name != nil {
		props["name"] = *result.Name
	} else {
		props["name"] = aliasName
	}
	if result.ID != nil {
		props["id"] = *result.ID
	}
	// azureDnsRecord is the fully qualified alias hostname Azure assigns; read-only.
	if result.Properties != nil && result.Properties.AzureDNSRecord != nil {
		props["azureDnsRecord"] = *result.Properties.AzureDNSRecord
	}

	return json.Marshal(props)
}

func (a *SqlServerDnsAlias) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]any
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, _ := props["resourceGroupName"].(string)
	if rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	serverName, _ := props["serverName"].(string)
	if serverName == "" {
		return nil, fmt.Errorf("serverName is required")
	}
	aliasName, _ := props["name"].(string)
	if aliasName == "" {
		aliasName = request.Label
	}
	if aliasName == "" {
		return nil, fmt.Errorf("name is required")
	}

	poller, err := a.api.BeginCreateOrUpdate(ctx, rgName, serverName, aliasName, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	expectedID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Sql/servers/%s/dnsAliases/%s",
		a.config.SubscriptionId, rgName, serverName, aliasName)

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
		propsJSON, err := serializeSQLServerDNSAliasProperties(result.ServerDNSAlias, rgName, serverName, aliasName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize ServerDnsAlias properties: %w", err)
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

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpCreate, token, expectedID)
	if err != nil {
		return nil, err
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        expectedID,
		},
	}, nil
}

func (a *SqlServerDnsAlias) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, serverName, aliasName, err := sqlServerDNSAliasIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, serverName, aliasName, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := serializeSQLServerDNSAliasProperties(result.ServerDNSAlias, rgName, serverName, aliasName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ServerDnsAlias properties: %w", err)
	}

	return &resource.ReadResult{
		ResourceType: ResourceTypeSQLServerDNSAlias,
		Properties:   string(propsJSON),
	}, nil
}

// Update re-reads current state without writing. Every field of an alias is either
// createOnly (its name, its parent server) or read-only (azureDnsRecord), so there is
// nothing ARM would accept in a PUT.
//
// Repointing an existing alias at a different server is ARM's separate `acquire`
// operation, which moves the alias between servers. That is a distinct intent from
// "reconcile this resource" and is deliberately not wired to Update: doing so would
// let an edited forma silently steal an alias from another server.
func (a *SqlServerDnsAlias) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, serverName, aliasName, err := sqlServerDNSAliasIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, serverName, aliasName, nil)
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

	propsJSON, err := serializeSQLServerDNSAliasProperties(result.ServerDNSAlias, rgName, serverName, aliasName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize ServerDnsAlias properties: %w", err)
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

func (a *SqlServerDnsAlias) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, serverName, aliasName, err := sqlServerDNSAliasIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := a.api.BeginDelete(ctx, rgName, serverName, aliasName, nil)
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
		}, fmt.Errorf("failed to delete ServerDnsAlias: %w", err)
	}

	if poller.Done() {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			},
		}, nil
	}

	token, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}
	reqID, err := encodeLROStart(lroOpDelete, token, request.NativeID)
	if err != nil {
		return nil, err
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       reqID,
			NativeID:        request.NativeID,
		},
	}, nil
}

func (a *SqlServerDnsAlias) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	reqID, err := decodeLROStatus(request.RequestID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	switch reqID.OperationType {
	case lroOpCreate, lroOpUpdate:
		return statusLRO(ctx, request, &reqID, resource.OperationCreate,
			func(token string) (*runtime.Poller[armsql.ServerDNSAliasesClientCreateOrUpdateResponse], error) {
				return resumePoller[armsql.ServerDNSAliasesClientCreateOrUpdateResponse](a.pipeline, token)
			},
			func(_ context.Context, result armsql.ServerDNSAliasesClientCreateOrUpdateResponse, _ resource.Operation) (string, json.RawMessage, error) {
				rgName, serverName, aliasName, err := sqlServerDNSAliasIDParts(*result.ID)
				if err != nil {
					return "", nil, err
				}
				propsJSON, err := serializeSQLServerDNSAliasProperties(result.ServerDNSAlias, rgName, serverName, aliasName)
				if err != nil {
					return "", nil, fmt.Errorf("failed to serialize ServerDnsAlias properties: %w", err)
				}
				return *result.ID, propsJSON, nil
			})
	case lroOpDelete:
		return statusDeleteLRO(ctx, request, &reqID,
			func(token string) (*runtime.Poller[armsql.ServerDNSAliasesClientDeleteResponse], error) {
				return resumePoller[armsql.ServerDNSAliasesClientDeleteResponse](a.pipeline, token)
			}, nil)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown LRO operation type: %s", reqID.OperationType)
	}
}

func (a *SqlServerDnsAlias) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	serverName := request.AdditionalProperties["serverName"]

	var nativeIDs []string
	pager := a.api.NewListByServerPager(rgName, serverName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list SQL server DNS aliases for server %s: %w", serverName, err)
		}
		for _, alias := range page.Value {
			if alias.ID != nil {
				nativeIDs = append(nativeIDs, *alias.ID)
			}
		}
	}

	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
