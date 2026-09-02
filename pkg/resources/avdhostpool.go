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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/desktopvirtualization/armdesktopvirtualization"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeAvdHostPool = "AZURE::DesktopVirtualization::HostPool"

// avdHostPoolsAPI is the armdesktopvirtualization surface used here. Every verb
// in the whole module is synchronous — there is no BeginX anywhere in
// armdesktopvirtualization, so Status never has real work to do for any AVD
// type.
//
// Note the shape of Update: the patch body travels in the options struct rather
// than as a parameter, which is how autorest renders an optional request body.
type avdHostPoolsAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, hostPoolName string, hostPool armdesktopvirtualization.HostPool, options *armdesktopvirtualization.HostPoolsClientCreateOrUpdateOptions) (armdesktopvirtualization.HostPoolsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, hostPoolName string, options *armdesktopvirtualization.HostPoolsClientGetOptions) (armdesktopvirtualization.HostPoolsClientGetResponse, error)
	Update(ctx context.Context, resourceGroupName string, hostPoolName string, options *armdesktopvirtualization.HostPoolsClientUpdateOptions) (armdesktopvirtualization.HostPoolsClientUpdateResponse, error)
	Delete(ctx context.Context, resourceGroupName string, hostPoolName string, options *armdesktopvirtualization.HostPoolsClientDeleteOptions) (armdesktopvirtualization.HostPoolsClientDeleteResponse, error)
	NewListPager(options *armdesktopvirtualization.HostPoolsClientListOptions) *runtime.Pager[armdesktopvirtualization.HostPoolsClientListResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armdesktopvirtualization.HostPoolsClientListByResourceGroupOptions) *runtime.Pager[armdesktopvirtualization.HostPoolsClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeAvdHostPool, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &AvdHostPool{api: c.AvdHostPoolsClient, config: cfg}
	})
}

// AvdHostPool is the provisioner for Azure Virtual Desktop host pools
// (Microsoft.DesktopVirtualization/hostPools).
//
// The pool is the anchor of AVD: application groups reference it, scaling
// plans drive it, and session hosts register into it. A pool with zero session
// hosts is a valid and free ARM record, and no session host is modelled here.
//
// The session-host registration token is never surfaced as a property: ARM
// returns it only from a separate RetrieveRegistrationToken call, so putting it
// in resource state would persist a live joining credential.
type AvdHostPool struct {
	api    avdHostPoolsAPI
	config *config.Config
}

// avdRegistrationInfoProps mirrors the RegistrationInfo class in
// schema/pkl/desktopvirtualization/avdhostpool.pkl.
type avdRegistrationInfoProps struct {
	RegistrationTokenOperation string `json:"registrationTokenOperation"`
	ExpirationTime             string `json:"expirationTime"`
}

// avdHostPoolProps mirrors schema/pkl/desktopvirtualization/avdhostpool.pkl.
type avdHostPoolProps struct {
	Name                          string                    `json:"name"`
	Location                      string                    `json:"location"`
	ResourceGroupName             string                    `json:"resourceGroupName"`
	HostPoolType                  string                    `json:"hostPoolType"`
	LoadBalancerType              string                    `json:"loadBalancerType"`
	PreferredAppGroupType         string                    `json:"preferredAppGroupType"`
	PersonalDesktopAssignmentType string                    `json:"personalDesktopAssignmentType"`
	MaxSessionLimit               *int32                    `json:"maxSessionLimit"`
	Description                   string                    `json:"description"`
	FriendlyName                  string                    `json:"friendlyName"`
	StartVmOnConnect              *bool                     `json:"startVmOnConnect"`
	ValidationEnvironment         *bool                     `json:"validationEnvironment"`
	RegistrationInfo              *avdRegistrationInfoProps `json:"registrationInfo"`
}

func avdHostPoolIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "hostpools")
	if err != nil {
		return "", "", err
	}
	return rgName, names["hostpools"], nil
}

// avdRegistrationInfo builds the ARM registrationInfo block. It is write-only:
// ARM never answers Get with the operation verb that was sent, and it
// re-serialises the expiry, so nothing here is ever read back.
//
// Only `Update` mints a token, and ARM demands an expiry in the 1-hour-to-30-day
// window when it does, so an Update with no expirationTime is refused here
// rather than sent and rejected with an opaque BadRequest.
func avdRegistrationInfo(info *avdRegistrationInfoProps) (*armdesktopvirtualization.RegistrationInfo, error) {
	if info == nil || info.RegistrationTokenOperation == "" {
		return nil, nil
	}
	out := &armdesktopvirtualization.RegistrationInfo{
		RegistrationTokenOperation: to.Ptr(
			armdesktopvirtualization.RegistrationTokenOperation(info.RegistrationTokenOperation)),
	}
	if info.ExpirationTime != "" {
		expiry, err := parseTime(info.ExpirationTime)
		if err != nil {
			return nil, fmt.Errorf("registrationInfo.expirationTime: %w", err)
		}
		out.ExpirationTime = to.Ptr(expiry)
	} else if info.RegistrationTokenOperation == string(armdesktopvirtualization.RegistrationTokenOperationUpdate) {
		return nil, fmt.Errorf(
			"registrationInfo.expirationTime is required when registrationTokenOperation is Update")
	}
	return out, nil
}

func (a *AvdHostPool) buildPropertiesFromResult(pool *armdesktopvirtualization.HostPool, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if pool.ID != nil {
		props["id"] = *pool.ID
	}
	if pool.Name != nil {
		props["name"] = *pool.Name
	}
	if pool.Location != nil {
		props["location"] = normalizeAzureLocation(*pool.Location)
	}

	if p := pool.Properties; p != nil {
		if p.HostPoolType != nil {
			props["hostPoolType"] = canonicalizeEnum(string(*p.HostPoolType),
				"Pooled", "Personal", "BYODesktop")
		}
		if p.LoadBalancerType != nil {
			props["loadBalancerType"] = canonicalizeEnum(string(*p.LoadBalancerType),
				"BreadthFirst", "DepthFirst", "Persistent")
		}
		if p.PreferredAppGroupType != nil {
			props["preferredAppGroupType"] = canonicalizeEnum(string(*p.PreferredAppGroupType),
				"Desktop", "None", "RailApplications")
		}
		if p.PersonalDesktopAssignmentType != nil {
			props["personalDesktopAssignmentType"] = canonicalizeEnum(
				string(*p.PersonalDesktopAssignmentType), "Automatic", "Direct")
		}
		if p.MaxSessionLimit != nil {
			props["maxSessionLimit"] = *p.MaxSessionLimit
		}
		// ARM answers Get with "" for a description or friendly name that was
		// never set, and desired state carries the field absent — emitting the
		// empty string would report drift on every sync.
		if p.Description != nil && *p.Description != "" {
			props["description"] = *p.Description
		}
		if p.FriendlyName != nil && *p.FriendlyName != "" {
			props["friendlyName"] = *p.FriendlyName
		}
		if p.StartVMOnConnect != nil {
			props["startVmOnConnect"] = *p.StartVMOnConnect
		}
		if p.ValidationEnvironment != nil {
			props["validationEnvironment"] = *p.ValidationEnvironment
		}
		// registrationInfo is write-only and deliberately not emitted: the token
		// is a live credential ARM only hands out from RetrieveRegistrationToken,
		// the operation is an imperative verb rather than state, and the service
		// rewrites the expiry.
		//
		// applicationGroupReferences, objectId and cloudPcResource are also
		// dropped: the first grows every time an application group points at this
		// pool, and neither of the others is desired state.
	}

	if tags := azureTagsToFormaeTags(pool.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func (a *AvdHostPool) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props avdHostPoolProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.Location == "" {
		return nil, fmt.Errorf("location is required")
	}
	if props.HostPoolType == "" {
		return nil, fmt.Errorf("hostPoolType is required")
	}
	if props.LoadBalancerType == "" {
		return nil, fmt.Errorf("loadBalancerType is required")
	}
	if props.PreferredAppGroupType == "" {
		return nil, fmt.Errorf("preferredAppGroupType is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	registrationInfo, err := avdRegistrationInfo(props.RegistrationInfo)
	if err != nil {
		return nil, err
	}

	params := armdesktopvirtualization.HostPool{
		Location: to.Ptr(props.Location),
		Properties: &armdesktopvirtualization.HostPoolProperties{
			HostPoolType:          to.Ptr(armdesktopvirtualization.HostPoolType(props.HostPoolType)),
			LoadBalancerType:      to.Ptr(armdesktopvirtualization.LoadBalancerType(props.LoadBalancerType)),
			PreferredAppGroupType: to.Ptr(armdesktopvirtualization.PreferredAppGroupType(props.PreferredAppGroupType)),
			MaxSessionLimit:       props.MaxSessionLimit,
			StartVMOnConnect:      props.StartVmOnConnect,
			ValidationEnvironment: props.ValidationEnvironment,
			RegistrationInfo:      registrationInfo,
		},
	}
	if props.PersonalDesktopAssignmentType != "" {
		params.Properties.PersonalDesktopAssignmentType = to.Ptr(
			armdesktopvirtualization.PersonalDesktopAssignmentType(props.PersonalDesktopAssignmentType))
	}
	if props.Description != "" {
		params.Properties.Description = to.Ptr(props.Description)
	}
	if props.FriendlyName != "" {
		params.Properties.FriendlyName = to.Ptr(props.FriendlyName)
	}
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := a.api.CreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
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
	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.HostPool, props.ResourceGroupName))
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

func (a *AvdHostPool) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := avdHostPoolIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := a.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.HostPool, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeAvdHostPool,
		Properties:   string(propsJSON),
	}, nil
}

// Update is a synchronous PATCH. hostPoolType is createOnly because ARM's patch
// body has no field for it; everything else the schema declares as mutable is
// present in HostPoolPatchProperties.
func (a *AvdHostPool) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, name, err := avdHostPoolIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props avdHostPoolProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	registrationInfo, err := avdRegistrationInfo(props.RegistrationInfo)
	if err != nil {
		return nil, err
	}

	patchProps := &armdesktopvirtualization.HostPoolPatchProperties{
		MaxSessionLimit:       props.MaxSessionLimit,
		StartVMOnConnect:      props.StartVmOnConnect,
		ValidationEnvironment: props.ValidationEnvironment,
	}
	if props.LoadBalancerType != "" {
		patchProps.LoadBalancerType = to.Ptr(armdesktopvirtualization.LoadBalancerType(props.LoadBalancerType))
	}
	if props.PreferredAppGroupType != "" {
		patchProps.PreferredAppGroupType = to.Ptr(
			armdesktopvirtualization.PreferredAppGroupType(props.PreferredAppGroupType))
	}
	if props.PersonalDesktopAssignmentType != "" {
		patchProps.PersonalDesktopAssignmentType = to.Ptr(
			armdesktopvirtualization.PersonalDesktopAssignmentType(props.PersonalDesktopAssignmentType))
	}
	if props.Description != "" {
		patchProps.Description = to.Ptr(props.Description)
	}
	if props.FriendlyName != "" {
		patchProps.FriendlyName = to.Ptr(props.FriendlyName)
	}
	if registrationInfo != nil {
		patchProps.RegistrationInfo = &armdesktopvirtualization.RegistrationInfoPatch{
			RegistrationTokenOperation: registrationInfo.RegistrationTokenOperation,
			ExpirationTime:             registrationInfo.ExpirationTime,
		}
	}

	patch := &armdesktopvirtualization.HostPoolPatch{Properties: patchProps}
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		patch.Tags = azureTags
	}

	result, err := a.api.Update(ctx, rgName, name,
		&armdesktopvirtualization.HostPoolsClientUpdateOptions{HostPool: patch})
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

	propsJSON, err := json.Marshal(a.buildPropertiesFromResult(&result.HostPool, rgName))
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

// Delete passes force: a pool with a session host still registered is refused
// otherwise, and since no session host is modelled here such a host can only
// have arrived out of band — leaving the pool undeletable would leak it.
func (a *AvdHostPool) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := avdHostPoolIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	options := &armdesktopvirtualization.HostPoolsClientDeleteOptions{Force: to.Ptr(true)}
	if _, err := a.api.Delete(ctx, rgName, name, options); err != nil && !isDeleteSuccessError(err) {
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

// Status is never reached with real work to do: armdesktopvirtualization exposes
// no LRO at all, so every operation finishes inside its own call.
func (a *AvdHostPool) Status(_ context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus: resource.OperationStatusSuccess,
			RequestID:       request.RequestID,
		},
	}, nil
}

func (a *AvdHostPool) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := a.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list AVD host pools: %w", err)
			}
			for _, pool := range page.Value {
				if pool.ID != nil {
					nativeIDs = append(nativeIDs, *pool.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := a.api.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list AVD host pools: %w", err)
		}
		for _, pool := range page.Value {
			if pool.ID != nil {
				nativeIDs = append(nativeIDs, *pool.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
