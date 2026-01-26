// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package config

import (
	"context"
	"encoding/json"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/platform-engineering-labs/formae/pkg/model"
)

// Config holds Azure-specific configuration extracted from a Target.
type Config struct {
	SubscriptionId string
}

// FromTarget extracts Azure configuration from a Formae Target.
func FromTarget(target *model.Target) *Config {
	if target == nil || target.Config == nil {
		return &Config{}
	}

	return FromTargetConfig(target.Config)
}

// FromTargetConfig extracts Azure configuration from target config JSON.
func FromTargetConfig(targetConfig json.RawMessage) *Config {
	if targetConfig == nil {
		return &Config{}
	}

	var cfg map[string]interface{}
	if err := json.Unmarshal(targetConfig, &cfg); err != nil {
		return &Config{}
	}

	subscriptionID, _ := cfg["SubscriptionId"].(string)
	return &Config{
		SubscriptionId: subscriptionID,
	}
}

// ToAzureCredential creates Azure credentials using the default credential chain.
// This uses DefaultAzureCredential which tries multiple authentication methods:
// - Environment variables (AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID)
// - Managed Identity
// - Azure CLI
// - Azure PowerShell
// - etc.
func (c *Config) ToAzureCredential(ctx context.Context) (azcore.TokenCredential, error) {
	return azidentity.NewDefaultAzureCredential(nil)
}
