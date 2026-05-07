// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
)

func parseARMResourceID(resourceID string) (*arm.ResourceID, error) {
	if strings.TrimSpace(resourceID) == "" {
		return nil, fmt.Errorf("ARM ID is required")
	}
	id, err := arm.ParseResourceID(resourceID)
	if err != nil {
		return nil, fmt.Errorf("invalid ARM ID %q: %w", resourceID, err)
	}
	return id, nil
}

func armNameByType(id *arm.ResourceID, resourceType string) (string, bool) {
	for cur := id; cur != nil; cur = cur.Parent {
		types := cur.ResourceType.Types
		if len(types) == 0 {
			continue
		}
		if strings.EqualFold(types[len(types)-1], resourceType) && cur.Name != "" {
			return cur.Name, true
		}
	}
	return "", false
}

func armResourceGroup(id *arm.ResourceID, resourceID string) (string, error) {
	if id.ResourceGroupName == "" {
		return "", fmt.Errorf("ARM ID missing resource group: %s", resourceID)
	}
	return id.ResourceGroupName, nil
}

func armRequired(id *arm.ResourceID, resourceType, resourceID string) (string, error) {
	name, ok := armNameByType(id, resourceType)
	if !ok {
		return "", fmt.Errorf("ARM ID missing %s: %s", resourceType, resourceID)
	}
	return name, nil
}

func armIDParts(resourceID string, resourceTypes ...string) (rgName string, names map[string]string, err error) {
	id, err := parseARMResourceID(resourceID)
	if err != nil {
		return "", nil, err
	}
	rgName, err = armResourceGroup(id, resourceID)
	if err != nil {
		return "", nil, err
	}
	names = make(map[string]string, len(resourceTypes))
	for _, resourceType := range resourceTypes {
		name, err := armRequired(id, resourceType, resourceID)
		if err != nil {
			return "", nil, err
		}
		names[resourceType] = name
	}
	return rgName, names, nil
}

func diskIDParts(resourceID string) (rgName, diskName string, err error) {
	rgName, names, err := armIDParts(resourceID, "disks")
	if err != nil {
		return "", "", err
	}
	return rgName, names["disks"], nil
}

func privateEndpointIDParts(resourceID string) (rgName, peName string, err error) {
	rgName, names, err := armIDParts(resourceID, "privateendpoints")
	if err != nil {
		return "", "", err
	}
	return rgName, names["privateendpoints"], nil
}

func privateDnsZoneGroupIDParts(resourceID string) (rgName, peName, groupName string, err error) {
	rgName, names, err := armIDParts(resourceID, "privateendpoints", "privatednszonegroups")
	if err != nil {
		return "", "", "", err
	}
	return rgName, names["privateendpoints"], names["privatednszonegroups"], nil
}
