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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kubernetesconfiguration/armkubernetesconfiguration"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeFluxConfiguration = "Azure::KubernetesConfiguration::FluxConfiguration"

func init() {
	registry.Register(ResourceTypeFluxConfiguration, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &FluxConfiguration{client, cfg}
	})
}

type FluxConfiguration struct {
	Client *client.Client
	Config *config.Config
}

func serializeFluxConfigurationProperties(result armkubernetesconfiguration.FluxConfiguration, rgName, clusterName string) (json.RawMessage, error) {
	props := make(map[string]interface{})

	if result.ID != nil {
		props["id"] = *result.ID
	}
	if result.Name != nil {
		props["name"] = *result.Name
	}
	props["resourceGroupName"] = rgName
	props["clusterName"] = clusterName

	if result.Properties != nil {
		if result.Properties.SourceKind != nil {
			props["sourceKind"] = string(*result.Properties.SourceKind)
		}
		if result.Properties.Scope != nil {
			props["scope"] = string(*result.Properties.Scope)
		}
		if result.Properties.Namespace != nil {
			props["namespace"] = *result.Properties.Namespace
		}
		if result.Properties.Suspend != nil {
			props["suspend"] = *result.Properties.Suspend
		}

		// Git repository
		if result.Properties.GitRepository != nil {
			gr := result.Properties.GitRepository
			gitRepo := make(map[string]interface{})
			if gr.URL != nil {
				gitRepo["url"] = *gr.URL
			}
			if gr.RepositoryRef != nil {
				ref := make(map[string]interface{})
				if gr.RepositoryRef.Branch != nil {
					ref["branch"] = *gr.RepositoryRef.Branch
				}
				if gr.RepositoryRef.Commit != nil {
					ref["commit"] = *gr.RepositoryRef.Commit
				}
				if gr.RepositoryRef.Semver != nil {
					ref["semver"] = *gr.RepositoryRef.Semver
				}
				if gr.RepositoryRef.Tag != nil {
					ref["tag"] = *gr.RepositoryRef.Tag
				}
				if len(ref) > 0 {
					gitRepo["repositoryRef"] = ref
				}
			}
			if gr.SyncIntervalInSeconds != nil {
				gitRepo["syncIntervalInSeconds"] = *gr.SyncIntervalInSeconds
			}
			if gr.TimeoutInSeconds != nil {
				gitRepo["timeoutInSeconds"] = *gr.TimeoutInSeconds
			}
			if len(gitRepo) > 0 {
				props["gitRepository"] = gitRepo
			}
		}

		// Kustomizations
		if result.Properties.Kustomizations != nil {
			kustomizations := make(map[string]interface{}, len(result.Properties.Kustomizations))
			for name, k := range result.Properties.Kustomizations {
				if k == nil {
					continue
				}
				kDef := make(map[string]interface{})
				if k.Path != nil {
					kDef["path"] = *k.Path
				}
				if k.Prune != nil {
					kDef["prune"] = *k.Prune
				}
				if k.Force != nil {
					kDef["force"] = *k.Force
				}
				if k.SyncIntervalInSeconds != nil {
					kDef["syncIntervalInSeconds"] = *k.SyncIntervalInSeconds
				}
				if k.RetryIntervalInSeconds != nil {
					kDef["retryIntervalInSeconds"] = *k.RetryIntervalInSeconds
				}
				if k.TimeoutInSeconds != nil {
					kDef["timeoutInSeconds"] = *k.TimeoutInSeconds
				}
				if k.DependsOn != nil {
					deps := make([]string, 0, len(k.DependsOn))
					for _, d := range k.DependsOn {
						if d != nil {
							deps = append(deps, *d)
						}
					}
					kDef["dependsOn"] = deps
				}
				kustomizations[name] = kDef
			}
			if len(kustomizations) > 0 {
				props["kustomizations"] = kustomizations
			}
		}
	}

	return json.Marshal(props)
}

func parseFluxGitRepository(raw map[string]interface{}) *armkubernetesconfiguration.GitRepositoryDefinition {
	gr := &armkubernetesconfiguration.GitRepositoryDefinition{}
	if url, ok := raw["url"].(string); ok {
		gr.URL = to.Ptr(url)
	}
	if refRaw, ok := raw["repositoryRef"].(map[string]interface{}); ok {
		ref := &armkubernetesconfiguration.RepositoryRefDefinition{}
		if branch, ok := refRaw["branch"].(string); ok {
			ref.Branch = to.Ptr(branch)
		}
		if commit, ok := refRaw["commit"].(string); ok {
			ref.Commit = to.Ptr(commit)
		}
		if semver, ok := refRaw["semver"].(string); ok {
			ref.Semver = to.Ptr(semver)
		}
		if tag, ok := refRaw["tag"].(string); ok {
			ref.Tag = to.Ptr(tag)
		}
		gr.RepositoryRef = ref
	}
	if syncInterval, ok := raw["syncIntervalInSeconds"].(float64); ok {
		gr.SyncIntervalInSeconds = to.Ptr(int64(syncInterval))
	}
	if timeout, ok := raw["timeoutInSeconds"].(float64); ok {
		gr.TimeoutInSeconds = to.Ptr(int64(timeout))
	}
	if httpsCACert, ok := raw["httpsCACert"].(string); ok {
		gr.HTTPSCACert = to.Ptr(httpsCACert)
	}
	if httpsUser, ok := raw["httpsUser"].(string); ok {
		gr.HTTPSUser = to.Ptr(httpsUser)
	}
	if sshKnownHosts, ok := raw["sshKnownHosts"].(string); ok {
		gr.SSHKnownHosts = to.Ptr(sshKnownHosts)
	}
	if localAuthRef, ok := raw["localAuthRef"].(string); ok {
		gr.LocalAuthRef = to.Ptr(localAuthRef)
	}
	return gr
}

func parseFluxKustomizations(raw map[string]interface{}) map[string]*armkubernetesconfiguration.KustomizationDefinition {
	result := make(map[string]*armkubernetesconfiguration.KustomizationDefinition, len(raw))
	for name, v := range raw {
		kMap, ok := v.(map[string]interface{})
		if !ok {
			continue
		}
		k := &armkubernetesconfiguration.KustomizationDefinition{}
		if path, ok := kMap["path"].(string); ok {
			k.Path = to.Ptr(path)
		}
		if prune, ok := kMap["prune"].(bool); ok {
			k.Prune = to.Ptr(prune)
		}
		if force, ok := kMap["force"].(bool); ok {
			k.Force = to.Ptr(force)
		}
		if syncInterval, ok := kMap["syncIntervalInSeconds"].(float64); ok {
			k.SyncIntervalInSeconds = to.Ptr(int64(syncInterval))
		}
		if retryInterval, ok := kMap["retryIntervalInSeconds"].(float64); ok {
			k.RetryIntervalInSeconds = to.Ptr(int64(retryInterval))
		}
		if timeout, ok := kMap["timeoutInSeconds"].(float64); ok {
			k.TimeoutInSeconds = to.Ptr(int64(timeout))
		}
		if depsRaw, ok := kMap["dependsOn"].([]interface{}); ok {
			deps := make([]*string, 0, len(depsRaw))
			for _, d := range depsRaw {
				if s, ok := d.(string); ok {
					deps = append(deps, to.Ptr(s))
				}
			}
			k.DependsOn = deps
		}
		result[name] = k
	}
	return result
}

func buildFluxConfigurationParams(props map[string]interface{}) armkubernetesconfiguration.FluxConfiguration {
	params := armkubernetesconfiguration.FluxConfiguration{
		Properties: &armkubernetesconfiguration.FluxConfigurationProperties{},
	}

	if sourceKind, ok := props["sourceKind"].(string); ok {
		sk := armkubernetesconfiguration.SourceKindType(sourceKind)
		params.Properties.SourceKind = &sk
	}
	if scope, ok := props["scope"].(string); ok {
		s := armkubernetesconfiguration.ScopeType(scope)
		params.Properties.Scope = &s
	}
	if namespace, ok := props["namespace"].(string); ok {
		params.Properties.Namespace = to.Ptr(namespace)
	}
	if suspend, ok := props["suspend"].(bool); ok {
		params.Properties.Suspend = to.Ptr(suspend)
	}

	if grRaw, ok := props["gitRepository"].(map[string]interface{}); ok {
		params.Properties.GitRepository = parseFluxGitRepository(grRaw)
	}

	if kustRaw, ok := props["kustomizations"].(map[string]interface{}); ok {
		params.Properties.Kustomizations = parseFluxKustomizations(kustRaw)
	}

	return params
}

func (fc *FluxConfiguration) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props map[string]interface{}
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	clusterName, ok := props["clusterName"].(string)
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("clusterName is required")
	}

	fluxName, ok := props["name"].(string)
	if !ok || fluxName == "" {
		fluxName = request.Label
	}

	params := buildFluxConfigurationParams(props)

	poller, err := fc.Client.FluxConfigurationsClient.BeginCreateOrUpdate(ctx, rgName, aksClusterRP, aksClusterResourceName, clusterName, fluxName, params, nil)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.ContainerService/managedClusters/%s/providers/Microsoft.KubernetesConfiguration/fluxConfigurations/%s",
		fc.Config.SubscriptionId, rgName, clusterName, fluxName)

	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}

		propsJSON, err := serializeFluxConfigurationProperties(result.FluxConfiguration, rgName, clusterName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize flux configuration properties: %w", err)
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

	reqID := lroRequestID{
		OperationType: "create",
		ResumeToken:   resumeToken,
		NativeID:      expectedNativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (fc *FluxConfiguration) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, clusterName, fluxName, err := parseFluxConfigurationNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := fc.Client.FluxConfigurationsClient.Get(ctx, rgName, aksClusterRP, aksClusterResourceName, clusterName, fluxName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, nil
	}

	propsJSON, err := serializeFluxConfigurationProperties(result.FluxConfiguration, rgName, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize flux configuration properties: %w", err)
	}

	return &resource.ReadResult{
		Properties: string(propsJSON),
	}, nil
}

func (fc *FluxConfiguration) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, clusterName, fluxName, err := parseFluxConfigurationNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props map[string]interface{}
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// FluxConfiguration uses CreateOrUpdate for updates (not PATCH)
	params := buildFluxConfigurationParams(props)

	poller, err := fc.Client.FluxConfigurationsClient.BeginCreateOrUpdate(ctx, rgName, aksClusterRP, aksClusterResourceName, clusterName, fluxName, params, nil)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
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
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}

		propsJSON, err := serializeFluxConfigurationProperties(result.FluxConfiguration, rgName, clusterName)
		if err != nil {
			return nil, fmt.Errorf("failed to serialize flux configuration properties: %w", err)
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

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqID := lroRequestID{
		OperationType: "update",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (fc *FluxConfiguration) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, clusterName, fluxName, err := parseFluxConfigurationNativeID(request.NativeID)
	if err != nil {
		return nil, err
	}

	poller, err := fc.Client.FluxConfigurationsClient.BeginDelete(ctx, rgName, aksClusterRP, aksClusterResourceName, clusterName, fluxName, nil)
	if err != nil {
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
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
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start flux configuration deletion: %w", err)
	}

	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	reqID := lroRequestID{
		OperationType: "delete",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (fc *FluxConfiguration) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	var reqID lroRequestID
	if err := json.Unmarshal([]byte(request.RequestID), &reqID); err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to parse request ID: %w", err)
	}

	switch reqID.OperationType {
	case "create", "update":
		return fc.statusCreateOrUpdate(ctx, request, &reqID)
	case "delete":
		return fc.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (fc *FluxConfiguration) statusCreateOrUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	operation := resource.OperationCreate
	if reqID.OperationType == "update" {
		operation = resource.OperationUpdate
	}

	poller, err := fc.Client.ResumeCreateFluxConfigurationPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller: %w", err)
	}

	if poller.Done() {
		return fc.handleCreateOrUpdateComplete(ctx, request, poller, operation)
	}

	_, err = poller.Poll(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		return fc.handleCreateOrUpdateComplete(ctx, request, poller, operation)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       operation,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (fc *FluxConfiguration) handleCreateOrUpdateComplete(ctx context.Context, request *resource.StatusRequest, poller *runtime.Poller[armkubernetesconfiguration.FluxConfigurationsClientCreateOrUpdateResponse], operation resource.Operation) (*resource.StatusResult, error) {
	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       operation,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	parts := splitResourceID(*result.ID)
	rgName := parts["resourcegroups"]
	clusterName := parts["managedclusters"]

	propsJSON, err := serializeFluxConfigurationProperties(result.FluxConfiguration, rgName, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize flux configuration properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          operation,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (fc *FluxConfiguration) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	poller, err := fc.Client.ResumeDeleteFluxConfigurationPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, fmt.Errorf("failed to resume poller: %w", err)
	}

	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil && !isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	_, err = poller.Poll(ctx)
	if err != nil {
		if isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, nil
	}

	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil && !isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (fc *FluxConfiguration) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing FluxConfigurations")
	}

	clusterName, ok := request.AdditionalProperties["clusterName"]
	if !ok || clusterName == "" {
		return nil, fmt.Errorf("clusterName is required in AdditionalProperties for listing FluxConfigurations")
	}

	pager := fc.Client.FluxConfigurationsClient.NewListPager(resourceGroupName, aksClusterRP, aksClusterResourceName, clusterName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list flux configurations: %w", err)
		}

		for _, config := range page.Value {
			if config.ID == nil {
				continue
			}
			nativeIDs = append(nativeIDs, *config.ID)
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}

func parseFluxConfigurationNativeID(nativeID string) (rgName, clusterName, fluxName string, err error) {
	parts := splitResourceID(nativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: could not extract resource group name from %s", nativeID)
	}

	clusterName, ok = parts["managedclusters"]
	if !ok || clusterName == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: could not extract cluster name from %s", nativeID)
	}

	fluxName, ok = parts["fluxconfigurations"]
	if !ok || fluxName == "" {
		return "", "", "", fmt.Errorf("invalid NativeID: could not extract flux configuration name from %s", nativeID)
	}

	return rgName, clusterName, fluxName, nil
}
