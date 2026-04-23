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
	"github.com/platform-engineering-labs/formae/pkg/model"
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
func (p *Plugin) RateLimit() model.RateLimitConfig {
	// Azure ARM API has rate limits, but we'll start conservative
	return model.RateLimitConfig{
		Scope:                            model.RateLimitScopeNamespace,
		MaxRequestsPerSecondForNamespace: 10,
	}
}

// DiscoveryFilters returns filters to exclude certain resources from discovery.
func (p *Plugin) DiscoveryFilters() []model.MatchFilter {
	// TODO: Implement match filters for discovery
	return []model.MatchFilter{}
}

// LabelConfig returns the configuration for extracting human-readable labels
// from discovered resources.
//
// The RFC 9535 name-list selector pulls resourceGroupName and name out in
// selector order. The formae labeler joins multi-value query results with
// "-", producing labels like "rg-prod-web". Using "$.name" alone causes
// non-deterministic "-N" drift when two resources share a leaf name across
// resource groups or subscriptions — whichever is discovered second collides
// with the first in the unmanaged-label uniqueness check.
//
// Azure::Resources::ResourceGroup has no resourceGroupName property, so the
// selector returns just [name], yielding "myrg" — still unique within a
// subscription.
func (p *Plugin) LabelConfig() model.LabelConfig {
	return model.LabelConfig{
		DefaultQuery: "$['resourceGroupName','name']",
	}
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
	return prov.Create(ctx, request)
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
	return prov.Update(ctx, request)
}

// Delete removes an Azure resource.
func (p *Plugin) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
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
	return prov.Delete(ctx, request)
}

// Status checks the progress of an async operation.
func (p *Plugin) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
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
	return prov.Status(ctx, request)
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
