// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
)

const ResourceTypeDataProtectionBackupPolicyDisk = "AZURE::DataProtection::BackupPolicyDisk"

// datasourceDataProtectionBackupPolicyDisk is the datasourceTypes value ARM validates this policy's rule
// tree against. It is fixed per formae type rather than a user field: an arbitrary
// datasource/rule-tree pairing is rejected by ARM, and the four flavours are
// otherwise the same resource.
const datasourceDataProtectionBackupPolicyDisk = "Microsoft.Compute/disks"

func init() {
	registry.Register(ResourceTypeDataProtectionBackupPolicyDisk, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataProtectionBackupPolicyDisk{
			dataProtectionBackupPolicy: dataProtectionBackupPolicy{
				api:            c.DataProtectionBackupPoliciesClient,
				config:         cfg,
				resourceType:   ResourceTypeDataProtectionBackupPolicyDisk,
				datasourceType: datasourceDataProtectionBackupPolicyDisk,
			},
		}
	})
}

// DataProtectionBackupPolicyDisk is the provisioner for managed-disk backup policies.
// The whole implementation lives in dataprotectionpolicy.go, shared with the other
// three backup-policy flavours.
type DataProtectionBackupPolicyDisk struct {
	dataProtectionBackupPolicy
}
