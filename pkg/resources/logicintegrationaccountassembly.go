// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/logic/armlogic"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeLogicIntegrationAccountAssembly = "AZURE::Logic::IntegrationAccountAssembly"

// logicIntegrationAccountAssembliesAPI is the armlogic surface used here. Every
// verb is synchronous and there is no PATCH: an update is another
// CreateOrUpdate.
//
// ListContentCallbackURL is deliberately absent: it mints a SAS URL to the blob
// ARM copied the assembly into, which is a bearer credential.
type logicIntegrationAccountAssembliesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, integrationAccountName string, assemblyArtifactName string, assemblyArtifact armlogic.AssemblyDefinition, options *armlogic.IntegrationAccountAssembliesClientCreateOrUpdateOptions) (armlogic.IntegrationAccountAssembliesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, integrationAccountName string, assemblyArtifactName string, options *armlogic.IntegrationAccountAssembliesClientGetOptions) (armlogic.IntegrationAccountAssembliesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, integrationAccountName string, assemblyArtifactName string, options *armlogic.IntegrationAccountAssembliesClientDeleteOptions) (armlogic.IntegrationAccountAssembliesClientDeleteResponse, error)
	NewListPager(resourceGroupName string, integrationAccountName string, options *armlogic.IntegrationAccountAssembliesClientListOptions) *runtime.Pager[armlogic.IntegrationAccountAssembliesClientListResponse]
}

func init() {
	registry.Register(ResourceTypeLogicIntegrationAccountAssembly, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &LogicIntegrationAccountAssembly{
			api:    c.LogicIntegrationAccountAssembliesClient,
			config: cfg,
		}
	})
}

// LogicIntegrationAccountAssembly is the provisioner for .NET assemblies held in
// an integration account
// (Microsoft.Logic/integrationAccounts/assemblies), so an XSLT map can call into
// custom code.
type LogicIntegrationAccountAssembly struct {
	api    logicIntegrationAccountAssembliesAPI
	config *config.Config
}

// logicIntegrationAccountAssemblyProps mirrors
// schema/pkl/logic/logicintegrationaccountassembly.pkl.
//
// Name is the ARM child resource name; AssemblyName is the .NET identity
// recorded inside it. ARM requires both and they are independent.
type logicIntegrationAccountAssemblyProps struct {
	logicChildProps
	AssemblyName           string  `json:"assemblyName"`
	Content                string  `json:"content"`
	AssemblyVersion        *string `json:"assemblyVersion"`
	AssemblyCulture        *string `json:"assemblyCulture"`
	AssemblyPublicKeyToken *string `json:"assemblyPublicKeyToken"`
}

func (p *logicIntegrationAccountAssemblyProps) parse(payload json.RawMessage, fallbackName string) error {
	if err := json.Unmarshal(payload, p); err != nil {
		return fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if err := p.validate(fallbackName); err != nil {
		return err
	}
	if p.AssemblyName == "" {
		return fmt.Errorf("assemblyName is required")
	}
	if p.Content == "" {
		return fmt.Errorf("content is required")
	}
	return nil
}

// logicAssemblyContentType is the only value ARM accepts for an assembly.
// Omitting it fails the create with
//
//	The 'contentType' property of assembly 'conformance-assembly' must be set to
//	'application/octet-stream'.
//
// An assembly is always a .dll, so there is nothing for a caller to choose here
// and the schema deliberately exposes no field for it.
const logicAssemblyContentType = "application/octet-stream"

// params builds the request body shared by create and update.
//
// Content is typed `any` in the SDK because the same field carries a structured
// document for some artifact kinds; for an assembly it is the base64 of the
// .dll, so the caller's string goes across unchanged.
func (a *LogicIntegrationAccountAssembly) params(props logicIntegrationAccountAssemblyProps) armlogic.AssemblyDefinition {
	return armlogic.AssemblyDefinition{
		Properties: &armlogic.AssemblyProperties{
			AssemblyName:           to.Ptr(props.AssemblyName),
			Content:                props.Content,
			ContentType:            to.Ptr(logicAssemblyContentType),
			AssemblyVersion:        props.AssemblyVersion,
			AssemblyCulture:        props.AssemblyCulture,
			AssemblyPublicKeyToken: props.AssemblyPublicKeyToken,
		},
	}
}

func (a *LogicIntegrationAccountAssembly) buildPropertiesFromResult(assembly *armlogic.AssemblyDefinition, rgName, accountName string) map[string]any {
	props := logicChildBaseProps(rgName, accountName, assembly.ID, assembly.Name)

	if p := assembly.Properties; p != nil {
		if p.AssemblyName != nil {
			props["assemblyName"] = *p.AssemblyName
		}
		if p.AssemblyVersion != nil && *p.AssemblyVersion != "" {
			props["assemblyVersion"] = *p.AssemblyVersion
		}
		if p.AssemblyCulture != nil && *p.AssemblyCulture != "" {
			props["assemblyCulture"] = *p.AssemblyCulture
		}
		if p.AssemblyPublicKeyToken != nil && *p.AssemblyPublicKeyToken != "" {
			props["assemblyPublicKeyToken"] = *p.AssemblyPublicKeyToken
		}
		// content is declared writeOnly and is NOT read back: ARM answers a GET
		// with a contentLink SAS URL to the blob it copied the assembly into,
		// never with the bytes.
		//
		// contentLink is not read back either — the URL carries an embedded SAS
		// token and rotates on every read. metadata is arbitrary JSON the schema
		// cannot express, and the timestamps move on their own.
	}

	return props
}

func (a *LogicIntegrationAccountAssembly) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props logicIntegrationAccountAssemblyProps
	if err := props.parse(request.Properties, request.Label); err != nil {
		return nil, err
	}

	result, err := a.api.CreateOrUpdate(ctx, props.ResourceGroupName, props.IntegrationAccountName,
		props.Name, a.params(props), nil)
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
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AssemblyDefinition,
		props.ResourceGroupName, props.IntegrationAccountName))
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

func (a *LogicIntegrationAccountAssembly) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "assemblies")
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, accountName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AssemblyDefinition, rgName, accountName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeLogicIntegrationAccountAssembly,
		Properties:   string(propsJSON),
	}, nil
}

// Update reissues CreateOrUpdate: this API has no PATCH verb for assemblies.
func (a *LogicIntegrationAccountAssembly) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "assemblies")
	if err != nil {
		return nil, err
	}

	var props logicIntegrationAccountAssemblyProps
	if err := props.parse(request.DesiredProperties, name); err != nil {
		return nil, err
	}

	result, err := a.api.CreateOrUpdate(ctx, rgName, accountName, name, a.params(props), nil)
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.AssemblyDefinition, rgName, accountName))
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

func (a *LogicIntegrationAccountAssembly) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, accountName, name, err := logicChildIDParts(request.NativeID, "assemblies")
	if err != nil {
		return nil, err
	}

	if _, err := a.api.Delete(ctx, rgName, accountName, name, nil); err != nil && !isDeleteSuccessError(err) {
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

// Status echoes success: every verb this provisioner uses is synchronous.
func (a *LogicIntegrationAccountAssembly) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

// List needs both the resource group and the integration account: ARM has no
// subscription-wide listing of integration account assemblies.
func (a *LogicIntegrationAccountAssembly) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]
	accountName := request.AdditionalProperties["integrationAccountName"]
	if rgName == "" || accountName == "" {
		return &resource.ListResult{}, nil
	}

	var nativeIDs []string
	pager := a.api.NewListPager(rgName, accountName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list logic integration account assemblies: %w", err)
		}
		for _, assembly := range page.Value {
			if assembly != nil && assembly.ID != nil {
				nativeIDs = append(nativeIDs, *assembly.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
