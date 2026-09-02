// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeDataFactoryFactory = "AZURE::DataFactory::Factory"

// dataFactoryFactoriesAPI is the armdatafactory surface used here. Every verb is
// synchronous — there is no BeginX anywhere on FactoriesClient — so no poller is
// ever created and Status never has real work to do.
//
// Update (the narrow PATCH, which only accepts identity, tags and
// publicNetworkAccess) is deliberately absent: this provisioner reissues
// CreateOrUpdate so that repoConfiguration and purviewResourceId really reconcile.
type dataFactoryFactoriesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, factoryName string, factory armdatafactory.Factory, options *armdatafactory.FactoriesClientCreateOrUpdateOptions) (armdatafactory.FactoriesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, factoryName string, options *armdatafactory.FactoriesClientGetOptions) (armdatafactory.FactoriesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, factoryName string, options *armdatafactory.FactoriesClientDeleteOptions) (armdatafactory.FactoriesClientDeleteResponse, error)
	NewListPager(options *armdatafactory.FactoriesClientListOptions) *runtime.Pager[armdatafactory.FactoriesClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armdatafactory.FactoriesClientListByResourceGroupOptions) *runtime.Pager[armdatafactory.FactoriesClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeDataFactoryFactory, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataFactoryFactory{
			api:    c.DataFactoryFactoriesClient,
			config: cfg,
		}
	})
}

// DataFactoryFactory is the provisioner for Azure Data Factory v2 factories
// (Microsoft.DataFactory/factories).
//
// The factory is the parent of every other Data Factory resource: integration
// runtimes, linked services, datasets, pipelines, triggers and data flows all hang
// off it and are addressed by (resourceGroupName, factoryName).
type DataFactoryFactory struct {
	api    dataFactoryFactoriesAPI
	config *config.Config
}

func dataFactoryFactoryIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "factories")
	if err != nil {
		return "", "", err
	}
	return rgName, names["factories"], nil
}

// dataFactoryCanonicalJSON re-encodes a JSON document compactly with sorted keys.
//
// Several Data Factory bodies (a pipeline's activity list, most obviously) are
// arbitrarily nested JSON that no PKL class can describe, so they cross the wire as
// strings. Go's map encoding sorts keys, so a document is put through this before
// it is sent; without it a body that differed from the service's formatting only in
// whitespace or key order would look like a change on every apply.
//
// field names the property in the error message, so a bad document says which one.
func dataFactoryCanonicalJSON(field, document string) (any, error) {
	var parsed any
	if err := json.Unmarshal([]byte(document), &parsed); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON: %w", field, err)
	}
	return parsed, nil
}

// dataFactoryStringList reads a Listing<String> back out of parsed properties.
func dataFactoryStringList(props map[string]any, key string) []string {
	raw, ok := props[key].([]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, entry := range raw {
		if s, ok := entry.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// buildFactoryIdentity maps the schema's nested identity block onto ARM's.
//
// Returning nil leaves identity out of the request body entirely, which is what an
// undeclared identity must do: the service then applies its own default of a
// system-assigned identity.
func buildFactoryIdentity(props map[string]any) *armdatafactory.FactoryIdentity {
	raw, ok := props["identity"].(map[string]any)
	if !ok {
		return nil
	}
	identity := &armdatafactory.FactoryIdentity{}
	if v, ok := raw["type"].(string); ok && v != "" {
		identity.Type = to.Ptr(armdatafactory.FactoryIdentityType(v))
	}
	if ids := dataFactoryStringList(raw, "userAssignedIdentityIds"); len(ids) > 0 {
		identity.UserAssignedIdentities = make(map[string]any, len(ids))
		for _, id := range ids {
			identity.UserAssignedIdentities[id] = map[string]any{}
		}
	}
	if identity.Type == nil && len(identity.UserAssignedIdentities) == 0 {
		return nil
	}
	return identity
}

// buildFactoryRepoConfiguration maps the schema's nested repoConfiguration block
// onto one of ARM's two discriminated variants.
//
// lastCommitId is never sent: it moves whenever anyone commits through the factory
// UI, and writing it back would fight the service for ownership of a value the
// service maintains.
func buildFactoryRepoConfiguration(props map[string]any) (armdatafactory.FactoryRepoConfigurationClassification, error) {
	raw, ok := props["repoConfiguration"].(map[string]any)
	if !ok {
		return nil, nil
	}
	str := func(key string) string {
		v, _ := raw[key].(string)
		return v
	}
	kind := str("kind")
	accountName := str("accountName")
	repositoryName := str("repositoryName")
	collaborationBranch := str("collaborationBranch")
	rootFolder := str("rootFolder")
	if accountName == "" || repositoryName == "" || collaborationBranch == "" || rootFolder == "" {
		return nil, fmt.Errorf("repoConfiguration requires accountName, repositoryName, collaborationBranch and rootFolder")
	}

	switch kind {
	case "FactoryGitHubConfiguration":
		cfg := &armdatafactory.FactoryGitHubConfiguration{
			Type:                to.Ptr(kind),
			AccountName:         to.Ptr(accountName),
			RepositoryName:      to.Ptr(repositoryName),
			CollaborationBranch: to.Ptr(collaborationBranch),
			RootFolder:          to.Ptr(rootFolder),
		}
		if v := str("hostName"); v != "" {
			cfg.HostName = to.Ptr(v)
		}
		return cfg, nil
	case "FactoryVSTSConfiguration":
		projectName := str("projectName")
		if projectName == "" {
			return nil, fmt.Errorf("repoConfiguration requires projectName for FactoryVSTSConfiguration")
		}
		return &armdatafactory.FactoryVSTSConfiguration{
			Type:                to.Ptr(kind),
			AccountName:         to.Ptr(accountName),
			RepositoryName:      to.Ptr(repositoryName),
			CollaborationBranch: to.Ptr(collaborationBranch),
			RootFolder:          to.Ptr(rootFolder),
			ProjectName:         to.Ptr(projectName),
		}, nil
	default:
		return nil, fmt.Errorf("repoConfiguration kind must be FactoryGitHubConfiguration or FactoryVSTSConfiguration, got %q", kind)
	}
}

// buildFactoryParams constructs the create/update payload.
func buildFactoryParams(props map[string]any, location string, properties json.RawMessage) (armdatafactory.Factory, error) {
	factoryProps := &armdatafactory.FactoryProperties{}

	if v, ok := props["publicNetworkAccess"].(string); ok && v != "" {
		factoryProps.PublicNetworkAccess = to.Ptr(armdatafactory.PublicNetworkAccess(v))
	}
	if v, ok := props["purviewResourceId"].(string); ok && v != "" {
		factoryProps.PurviewConfiguration = &armdatafactory.PurviewConfiguration{
			PurviewResourceID: to.Ptr(v),
		}
	}
	repo, err := buildFactoryRepoConfiguration(props)
	if err != nil {
		return armdatafactory.Factory{}, err
	}
	if repo != nil {
		factoryProps.RepoConfiguration = repo
	}

	params := armdatafactory.Factory{
		Location:   to.Ptr(location),
		Properties: factoryProps,
		Identity:   buildFactoryIdentity(props),
	}
	if azureTags := formaeTagsToAzureTags(properties); azureTags != nil {
		params.Tags = azureTags
	}
	return params, nil
}

func (f *DataFactoryFactory) buildPropertiesFromResult(factory *armdatafactory.Factory, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if factory.ID != nil {
		props["id"] = *factory.ID
	}
	if factory.Name != nil {
		props["name"] = *factory.Name
	}
	if factory.Location != nil {
		props["location"] = normalizeAzureLocation(*factory.Location)
	}

	if p := factory.Properties; p != nil {
		if p.PublicNetworkAccess != nil {
			props["publicNetworkAccess"] = canonicalizeEnum(string(*p.PublicNetworkAccess), "Enabled", "Disabled")
		}
		if p.PurviewConfiguration != nil && p.PurviewConfiguration.PurviewResourceID != nil {
			props["purviewResourceId"] = *p.PurviewConfiguration.PurviewResourceID
		}
		if repo := factoryRepoConfigurationProps(p.RepoConfiguration); repo != nil {
			props["repoConfiguration"] = repo
		}
		// createTime, version and provisioningState are deliberately dropped:
		// the timestamp and the service version move on their own and none of
		// the three is desired state.
	}

	// The identity block is echoed with its type and, for user-assigned
	// identities, the ARM IDs. principalId and tenantId are lifted out to
	// top-level properties instead: a provider default on a field of a plain
	// nested class is not honoured, so read-only values must not live inside one.
	if id := factory.Identity; id != nil {
		identity := make(map[string]any)
		if id.Type != nil {
			identity["type"] = canonicalizeEnum(string(*id.Type),
				"SystemAssigned", "UserAssigned", "SystemAssigned,UserAssigned")
		}
		if len(id.UserAssignedIdentities) > 0 {
			ids := make([]string, 0, len(id.UserAssignedIdentities))
			for k := range id.UserAssignedIdentities {
				ids = append(ids, k)
			}
			// ARM hands these back as a map, so the order is arbitrary. Sorting
			// makes successive reads of an unchanged factory identical.
			sort.Strings(ids)
			identity["userAssignedIdentityIds"] = ids
		}
		if len(identity) > 0 {
			props["identity"] = identity
		}
		if id.PrincipalID != nil {
			props["identityPrincipalId"] = *id.PrincipalID
		}
		if id.TenantID != nil {
			props["identityTenantId"] = *id.TenantID
		}
	}

	if tags := azureTagsToFormaeTags(factory.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

// factoryRepoConfigurationProps is the read-path inverse of
// buildFactoryRepoConfiguration. Only the fields the schema models are surfaced —
// lastCommitId and the bring-your-own-app GitHub credentials are not.
func factoryRepoConfigurationProps(cfg armdatafactory.FactoryRepoConfigurationClassification) map[string]any {
	if cfg == nil {
		return nil
	}
	out := make(map[string]any)
	set := func(key string, value *string) {
		if value != nil && *value != "" {
			out[key] = *value
		}
	}

	switch c := cfg.(type) {
	case *armdatafactory.FactoryGitHubConfiguration:
		out["kind"] = "FactoryGitHubConfiguration"
		set("accountName", c.AccountName)
		set("repositoryName", c.RepositoryName)
		set("collaborationBranch", c.CollaborationBranch)
		set("rootFolder", c.RootFolder)
		set("hostName", c.HostName)
	case *armdatafactory.FactoryVSTSConfiguration:
		out["kind"] = "FactoryVSTSConfiguration"
		set("accountName", c.AccountName)
		set("repositoryName", c.RepositoryName)
		set("collaborationBranch", c.CollaborationBranch)
		set("rootFolder", c.RootFolder)
		set("projectName", c.ProjectName)
	default:
		// A variant this provider does not model: report nothing rather than a
		// half-populated block that would read as drift forever.
		return nil
	}
	return out
}

func (f *DataFactoryFactory) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
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
	name, _ := props["name"].(string)
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := buildFactoryParams(props, location, request.Properties)
	if err != nil {
		return nil, err
	}

	result, err := f.api.CreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	nativeID := ""
	if result.ID != nil {
		nativeID = *result.ID
	}
	propsJSON, err := json.Marshal(f.buildPropertiesFromResult(&result.Factory, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
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

func (f *DataFactoryFactory) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := dataFactoryFactoryIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := f.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(f.buildPropertiesFromResult(&result.Factory, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeDataFactoryFactory,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate rather than the narrow PATCH verb. FactoriesClient
// .Update only accepts identity, tags and publicNetworkAccess, so a factory whose
// repoConfiguration or purviewResourceId changed would silently never reconcile.
func (f *DataFactoryFactory) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := dataFactoryFactoryIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]any
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	location, _ := props["location"].(string)
	if location == "" {
		return nil, fmt.Errorf("location is required")
	}

	params, err := buildFactoryParams(props, location, request.DesiredProperties)
	if err != nil {
		return nil, err
	}

	result, err := f.api.CreateOrUpdate(ctx, rgName, name, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(f.buildPropertiesFromResult(&result.Factory, rgName))
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

// Delete removes the factory and everything inside it. Data Factory has no soft
// delete, so a deleted factory's pipelines and run history are gone for good.
func (f *DataFactoryFactory) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := dataFactoryFactoryIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := f.api.Delete(ctx, rgName, name, nil); err != nil && !isDeleteSuccessError(err) {
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
				StatusMessage:   err.Error(),
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

// Status echoes success: every FactoriesClient verb is synchronous, so no poller is
// ever handed out and nothing can still be running by the time this is asked.
func (f *DataFactoryFactory) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List enumerates factories in one resource group, falling back to the whole
// subscription when discovery has no resource group to scope by.
func (f *DataFactoryFactory) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string
	collect := func(values []*armdatafactory.Factory) {
		for _, factory := range values {
			if factory != nil && factory.ID != nil {
				nativeIDs = append(nativeIDs, *factory.ID)
			}
		}
	}

	if rgName != "" {
		pager := f.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list data factories: %w", err)
			}
			collect(page.Value)
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := f.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list data factories: %w", err)
		}
		collect(page.Value)
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}

// dataFactoryChildIDParts recovers (resourceGroup, factoryName, childName) from a
// native ID of any resource nested directly under a factory.
//
// childType is the ARM type segment: "integrationruntimes", "linkedservices",
// "pipelines", "datasets", "triggers" or "dataflows".
func dataFactoryChildIDParts(resourceID, childType string) (rgName, factoryName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "factories", strings.ToLower(childType))
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["factories"], names[strings.ToLower(childType)], nil
}
