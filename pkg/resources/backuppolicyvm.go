// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservicesbackup/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeBackupPolicyVM = "AZURE::RecoveryServices::BackupPolicyVM"

func init() {
	registry.Register(ResourceTypeBackupPolicyVM, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &BackupPolicyVM{
			backupPolicyCore: backupPolicyCore{
				api:      c.BackupProtectionPoliciesClient,
				listAPI:  c.BackupPoliciesListClient,
				pipeline: c.Pipeline(),
				config:   cfg,
			},
		}
	})
}

// BackupPolicyVM is the provisioner for an Azure VM backup policy — a
// Microsoft.RecoveryServices/vaults/backupPolicies resource whose polymorphic
// properties are an AzureIaaSVMProtectionPolicy.
type BackupPolicyVM struct {
	backupPolicyCore
}

// backupPolicyVMProps mirrors schema/pkl/recoveryservices/backuppolicyvm.pkl.
type backupPolicyVMProps struct {
	Name                          string               `json:"name"`
	ResourceGroupName             string               `json:"resourceGroupName"`
	VaultName                     string               `json:"vaultName"`
	TimeZone                      string               `json:"timeZone"`
	InstantRpRetentionRangeInDays *int32               `json:"instantRpRetentionRangeInDays"`
	BackupSchedule                backupPolicySchedule `json:"backupSchedule"`
	backupPolicyRetention
}

func (p *BackupPolicyVM) params(props backupPolicyVMProps) (armrecoveryservicesbackup.ProtectionPolicyResource, error) {
	schedule, err := backupPolicySimpleSchedule(props.BackupSchedule)
	if err != nil {
		return armrecoveryservicesbackup.ProtectionPolicyResource{}, err
	}
	retention, err := backupPolicyLongTermRetention(props.backupPolicyRetention, schedule.ScheduleRunTimes)
	if err != nil {
		return armrecoveryservicesbackup.ProtectionPolicyResource{}, err
	}

	policy := &armrecoveryservicesbackup.AzureIaaSVMProtectionPolicy{
		BackupManagementType: to.Ptr(string(armrecoveryservicesbackup.BackupManagementTypeAzureIaasVM)),
		PolicyType:           to.Ptr(armrecoveryservicesbackup.IAASVMPolicyTypeV1),
		SchedulePolicy:       schedule,
		RetentionPolicy:      retention,
	}
	if props.TimeZone != "" {
		policy.TimeZone = to.Ptr(props.TimeZone)
	}
	if props.InstantRpRetentionRangeInDays != nil {
		policy.InstantRpRetentionRangeInDays = props.InstantRpRetentionRangeInDays
	}

	return armrecoveryservicesbackup.ProtectionPolicyResource{Properties: policy}, nil
}

// backupPolicyVMProperties renders an AzureIaaSVMProtectionPolicy back into the
// schema shape. Anything the schema does not declare — protectedItemsCount,
// tieringPolicy, instantRPDetails, snapshotConsistencyType — is dropped rather
// than echoed, because a key with no schema field behind it reads as unexpected
// drift.
func backupPolicyVMProperties(policy *armrecoveryservicesbackup.ProtectionPolicyResource, rgName, vaultName string) map[string]any {
	props := map[string]any{
		"resourceGroupName": rgName,
		"vaultName":         vaultName,
	}

	if policy.ID != nil {
		props["id"] = *policy.ID
	}
	if policy.Name != nil {
		props["name"] = *policy.Name
	}

	vmPolicy, ok := policy.Properties.(*armrecoveryservicesbackup.AzureIaaSVMProtectionPolicy)
	if !ok || vmPolicy == nil {
		return props
	}

	if vmPolicy.TimeZone != nil {
		props["timeZone"] = *vmPolicy.TimeZone
	}
	if vmPolicy.InstantRpRetentionRangeInDays != nil {
		props["instantRpRetentionRangeInDays"] = *vmPolicy.InstantRpRetentionRangeInDays
	}
	if schedule := backupPolicyScheduleProps(vmPolicy.SchedulePolicy); schedule != nil {
		props["backupSchedule"] = schedule
	}
	backupPolicyRetentionProps(vmPolicy.RetentionPolicy, props)

	return props
}

func (p *BackupPolicyVM) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props backupPolicyVMProps
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}
	if props.VaultName == "" {
		return nil, fmt.Errorf("vaultName is required")
	}
	name := props.Name
	if name == "" {
		name = request.Label
	}
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}

	params, err := p.params(props)
	if err != nil {
		return nil, err
	}

	progress, err := p.write(ctx, resource.OperationCreate, props.ResourceGroupName, props.VaultName, name, params, backupPolicyVMProperties)
	if err != nil {
		return nil, err
	}
	return &resource.CreateResult{ProgressResult: progress}, nil
}

func (p *BackupPolicyVM) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	return p.read(ctx, ResourceTypeBackupPolicyVM, request.NativeID, backupPolicyVMProperties)
}

func (p *BackupPolicyVM) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, vaultName, policyName, err := backupPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props backupPolicyVMProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params, err := p.params(props)
	if err != nil {
		return nil, err
	}

	progress, err := p.write(ctx, resource.OperationUpdate, rgName, vaultName, policyName, params, backupPolicyVMProperties)
	if err != nil {
		return nil, err
	}
	progress.NativeID = request.NativeID
	return &resource.UpdateResult{ProgressResult: progress}, nil
}

func (p *BackupPolicyVM) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	return p.delete(ctx, request.NativeID)
}

func (p *BackupPolicyVM) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return p.status(ctx, request, backupPolicyVMProperties)
}

func (p *BackupPolicyVM) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	return p.list(ctx, request, string(armrecoveryservicesbackup.BackupManagementTypeAzureIaasVM),
		func(properties armrecoveryservicesbackup.ProtectionPolicyClassification) bool {
			_, ok := properties.(*armrecoveryservicesbackup.AzureIaaSVMProtectionPolicy)
			return ok
		})
}
