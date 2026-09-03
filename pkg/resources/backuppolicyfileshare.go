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

const ResourceTypeBackupPolicyFileShare = "AZURE::RecoveryServices::BackupPolicyFileShare"

func init() {
	registry.Register(ResourceTypeBackupPolicyFileShare, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &BackupPolicyFileShare{
			backupPolicyCore: backupPolicyCore{
				api:      c.BackupProtectionPoliciesClient,
				listAPI:  c.BackupPoliciesListClient,
				pipeline: c.Pipeline(),
				config:   cfg,
			},
		}
	})
}

// BackupPolicyFileShare is the provisioner for an Azure Files backup policy — the
// same Microsoft.RecoveryServices/vaults/backupPolicies resource as its VM
// sibling, but with AzureFileShareProtectionPolicy properties and the AzureStorage
// backup management type.
type BackupPolicyFileShare struct {
	backupPolicyCore
}

// backupPolicyFileShareProps mirrors
// schema/pkl/recoveryservices/backuppolicyfileshare.pkl.
type backupPolicyFileShareProps struct {
	Name              string               `json:"name"`
	ResourceGroupName string               `json:"resourceGroupName"`
	VaultName         string               `json:"vaultName"`
	TimeZone          string               `json:"timeZone"`
	BackupSchedule    backupPolicySchedule `json:"backupSchedule"`
	backupPolicyRetention
}

func (p *BackupPolicyFileShare) params(props backupPolicyFileShareProps) (armrecoveryservicesbackup.ProtectionPolicyResource, error) {
	schedule, err := backupPolicySimpleSchedule(props.BackupSchedule)
	if err != nil {
		return armrecoveryservicesbackup.ProtectionPolicyResource{}, err
	}
	if props.DailyRetention == nil {
		return armrecoveryservicesbackup.ProtectionPolicyResource{}, fmt.Errorf("dailyRetention is required for a file share policy")
	}
	retention, err := backupPolicyLongTermRetention(props.backupPolicyRetention, schedule.ScheduleRunTimes)
	if err != nil {
		return armrecoveryservicesbackup.ProtectionPolicyResource{}, err
	}

	policy := &armrecoveryservicesbackup.AzureFileShareProtectionPolicy{
		BackupManagementType: to.Ptr(string(armrecoveryservicesbackup.BackupManagementTypeAzureStorage)),
		WorkLoadType:         to.Ptr(armrecoveryservicesbackup.WorkloadTypeAzureFileShare),
		SchedulePolicy:       schedule,
		RetentionPolicy:      retention,
	}
	if props.TimeZone != "" {
		policy.TimeZone = to.Ptr(props.TimeZone)
	}

	return armrecoveryservicesbackup.ProtectionPolicyResource{Properties: policy}, nil
}

// backupPolicyFileShareProperties renders an AzureFileShareProtectionPolicy back
// into the schema shape. vaultRetentionPolicy and protectedItemsCount are not
// modelled and are deliberately dropped.
func backupPolicyFileShareProperties(policy *armrecoveryservicesbackup.ProtectionPolicyResource, rgName, vaultName string) map[string]any {
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

	sharePolicy, ok := policy.Properties.(*armrecoveryservicesbackup.AzureFileShareProtectionPolicy)
	if !ok || sharePolicy == nil {
		return props
	}

	if sharePolicy.TimeZone != nil {
		props["timeZone"] = *sharePolicy.TimeZone
	}
	if schedule := backupPolicyScheduleProps(sharePolicy.SchedulePolicy); schedule != nil {
		props["backupSchedule"] = schedule
	}
	backupPolicyRetentionProps(sharePolicy.RetentionPolicy, props)

	return props
}

func (p *BackupPolicyFileShare) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	var props backupPolicyFileShareProps
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

	progress, err := p.write(ctx, resource.OperationCreate, props.ResourceGroupName, props.VaultName, name, params, backupPolicyFileShareProperties)
	if err != nil {
		return nil, err
	}
	return &resource.CreateResult{ProgressResult: progress}, nil
}

func (p *BackupPolicyFileShare) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	return p.read(ctx, ResourceTypeBackupPolicyFileShare, request.NativeID, backupPolicyFileShareProperties)
}

func (p *BackupPolicyFileShare) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	rgName, vaultName, policyName, err := backupPolicyIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	var props backupPolicyFileShareProps
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	params, err := p.params(props)
	if err != nil {
		return nil, err
	}

	progress, err := p.write(ctx, resource.OperationUpdate, rgName, vaultName, policyName, params, backupPolicyFileShareProperties)
	if err != nil {
		return nil, err
	}
	progress.NativeID = request.NativeID
	return &resource.UpdateResult{ProgressResult: progress}, nil
}

func (p *BackupPolicyFileShare) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	return p.delete(ctx, request.NativeID)
}

func (p *BackupPolicyFileShare) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	return p.status(ctx, request, backupPolicyFileShareProperties)
}

func (p *BackupPolicyFileShare) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	return p.list(ctx, request, string(armrecoveryservicesbackup.BackupManagementTypeAzureStorage),
		func(properties armrecoveryservicesbackup.ProtectionPolicyClassification) bool {
			_, ok := properties.(*armrecoveryservicesbackup.AzureFileShareProtectionPolicy)
			return ok
		})
}
