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

const ResourceTypeDataProtectionBackupPolicyKubernetesCluster = "AZURE::DataProtection::BackupPolicyKubernetesCluster"

// datasourceDataProtectionBackupPolicyKubernetesCluster is the datasourceTypes value ARM validates this policy's rule
// tree against. It is fixed per formae type rather than a user field: an arbitrary
// datasource/rule-tree pairing is rejected by ARM, and the four flavours are
// otherwise the same resource.
const datasourceDataProtectionBackupPolicyKubernetesCluster = "Microsoft.ContainerService/managedClusters"

func init() {
	registry.Register(ResourceTypeDataProtectionBackupPolicyKubernetesCluster, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &DataProtectionBackupPolicyKubernetesCluster{
			dataProtectionBackupPolicy: dataProtectionBackupPolicy{
				api:            c.DataProtectionBackupPoliciesClient,
				config:         cfg,
				resourceType:   ResourceTypeDataProtectionBackupPolicyKubernetesCluster,
				datasourceType: datasourceDataProtectionBackupPolicyKubernetesCluster,
			},
		}
	})
}

// DataProtectionBackupPolicyKubernetesCluster is the provisioner for AKS managed-cluster backup policies.
// The whole implementation lives in dataprotectionpolicy.go, shared with the other
// three backup-policy flavours.
type DataProtectionBackupPolicyKubernetesCluster struct {
	dataProtectionBackupPolicy
}
