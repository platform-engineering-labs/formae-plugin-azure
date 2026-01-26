// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package registry

import (
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
)

// ProvisionerFactory is a function that creates a Provisioner instance.
type ProvisionerFactory func(client *client.Client, cfg *config.Config) prov.Provisioner

// registry stores provisioner factories for each resource type.
// Schema and descriptor information is now extracted from Pkl at startup (see init.go).
var registry = make(map[string]ProvisionerFactory)

// Register registers a provisioner factory for a resource type.
// Schema information is extracted from Pkl schemas; only the provisioner factory is registered here.
func Register(resourceType string, factory ProvisionerFactory) {
	registry[resourceType] = factory
}

// Get returns a Provisioner instance for the given resource type.
func Get(resourceType string, client *client.Client, cfg *config.Config) prov.Provisioner {
	factory, ok := registry[resourceType]
	if !ok {
		return nil
	}
	return factory(client, cfg)
}

// HasProvisioner returns true if a provisioner is registered for the given resource type.
func HasProvisioner(resourceType string) bool {
	_, ok := registry[resourceType]
	return ok
}
