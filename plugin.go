// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"fmt"

	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/nativeid"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"

	// Import resources to trigger init() registration
	_ "github.com/platform-engineering-labs/formae-plugin-azure/pkg/resources"
)

// Plugin implements the Formae ResourcePlugin interface.
// The SDK automatically provides identity methods (Name, Version, Namespace)
// by reading formae-plugin.pkl at startup.
type Plugin struct{}

// Compile-time check: Plugin must satisfy ResourcePlugin interface.
var _ plugin.ResourcePlugin = &Plugin{}

// =============================================================================
// Configuration Methods
// =============================================================================

// RateLimit returns the rate limiting configuration for this plugin.
func (p *Plugin) RateLimit() plugin.RateLimitConfig {
	// Azure ARM API has rate limits, but we'll start conservative
	return plugin.RateLimitConfig{
		Scope:                            plugin.RateLimitScopeNamespace,
		MaxRequestsPerSecondForNamespace: 10,
	}
}

// DiscoveryFilters returns filters to exclude certain resources from discovery.
func (p *Plugin) DiscoveryFilters() []plugin.MatchFilter {
	// TODO: Implement match filters for discovery
	return []plugin.MatchFilter{}
}

// LabelConfig returns the configuration for extracting human-readable labels
// from discovered resources.
func (p *Plugin) LabelConfig() plugin.LabelConfig {
	return plugin.LabelConfig{}
}

// =============================================================================
// CRUD Operations
// =============================================================================

// Create provisions a new Azure resource.
func (p *Plugin) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	targetConfig := config.FromTargetConfig(request.TargetConfig)
	azureClient, err := client.NewClient(targetConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure client: %w", err)
	}

	if !registry.HasProvisioner(request.ResourceType) {
		return nil, fmt.Errorf("unsupported resource type: %s", request.ResourceType)
	}

	prov := registry.Get(request.ResourceType, azureClient, targetConfig)
	result, err := prov.Create(ctx, request)
	if result != nil && result.ProgressResult != nil {
		result.ProgressResult.NativeID = nativeid.Encode(result.ProgressResult.NativeID).String()
	}
	return result, err
}

// Read retrieves the current state of an Azure resource.
func (p *Plugin) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	request.NativeID = nativeid.NativeID(request.NativeID).ArmID()

	targetConfig := config.FromTargetConfig(request.TargetConfig)
	azureClient, err := client.NewClient(targetConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure client: %w", err)
	}

	if !registry.HasProvisioner(request.ResourceType) {
		return nil, fmt.Errorf("unsupported resource type: %s", request.ResourceType)
	}

	prov := registry.Get(request.ResourceType, azureClient, targetConfig)
	return prov.Read(ctx, request)
}

// Update modifies an existing Azure resource.
func (p *Plugin) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	originalNativeID := request.NativeID
	request.NativeID = nativeid.NativeID(request.NativeID).ArmID()

	targetConfig := config.FromTargetConfig(request.TargetConfig)
	azureClient, err := client.NewClient(targetConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure client: %w", err)
	}

	if !registry.HasProvisioner(request.ResourceType) {
		return nil, fmt.Errorf("unsupported resource type: %s", request.ResourceType)
	}

	prov := registry.Get(request.ResourceType, azureClient, targetConfig)
	result, err := prov.Update(ctx, request)
	if result != nil && result.ProgressResult != nil {
		result.ProgressResult.NativeID = nativeid.ReEncode(originalNativeID, result.ProgressResult.NativeID).String()
	}
	return result, err
}

// Delete removes an Azure resource.
func (p *Plugin) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	originalNativeID := request.NativeID
	request.NativeID = nativeid.NativeID(request.NativeID).ArmID()

	targetConfig := config.FromTargetConfig(request.TargetConfig)
	azureClient, err := client.NewClient(targetConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure client: %w", err)
	}

	if !registry.HasProvisioner(request.ResourceType) {
		return nil, fmt.Errorf("unsupported resource type: %s", request.ResourceType)
	}

	prov := registry.Get(request.ResourceType, azureClient, targetConfig)
	result, err := prov.Delete(ctx, request)
	if result != nil && result.ProgressResult != nil {
		result.ProgressResult.NativeID = nativeid.ReEncode(originalNativeID, result.ProgressResult.NativeID).String()
	}
	return result, err
}

// Status checks the progress of an async operation.
func (p *Plugin) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	originalNativeID := request.NativeID
	request.NativeID = nativeid.NativeID(request.NativeID).ArmID()

	targetConfig := config.FromTargetConfig(request.TargetConfig)
	azureClient, err := client.NewClient(targetConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure client: %w", err)
	}

	if !registry.HasProvisioner(request.ResourceType) {
		return nil, fmt.Errorf("unsupported resource type: %s", request.ResourceType)
	}

	prov := registry.Get(request.ResourceType, azureClient, targetConfig)
	result, err := prov.Status(ctx, request)
	if result != nil && result.ProgressResult != nil {
		result.ProgressResult.NativeID = nativeid.ReEncode(originalNativeID, result.ProgressResult.NativeID).String()
	}
	return result, err
}

// List returns all resource identifiers of a given type for discovery.
func (p *Plugin) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	log := plugin.LoggerFromContext(ctx)
	log.Debug("List called",
		"resourceType", request.ResourceType,
		"additionalProperties", request.AdditionalProperties,
	)

	targetConfig := config.FromTargetConfig(request.TargetConfig)
	azureClient, err := client.NewClient(targetConfig)
	if err != nil {
		log.Error("Failed to create Azure client", "error", err)
		return nil, fmt.Errorf("failed to create Azure client: %w", err)
	}

	if !registry.HasProvisioner(request.ResourceType) {
		log.Error("Unsupported resource type", "resourceType", request.ResourceType)
		return nil, fmt.Errorf("unsupported resource type: %s", request.ResourceType)
	}

	prov := registry.Get(request.ResourceType, azureClient, targetConfig)
	result, err := prov.List(ctx, request)
	if err != nil {
		log.Error("List failed", "resourceType", request.ResourceType, "error", err)
		return result, err
	}

	log.Debug("List completed",
		"resourceType", request.ResourceType,
		"nativeIDCount", len(result.NativeIDs),
	)
	return result, nil
}
