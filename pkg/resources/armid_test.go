// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package resources

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestARMIDParts(t *testing.T) {
	t.Run("disk", func(t *testing.T) {
		id := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/disks/disk-1"
		wantRG := "rg-1"
		wantDisk := "disk-1"

		gotRG, gotDisk, err := diskIDParts(id)

		require.NoError(t, err)
		require.Equal(t, wantRG, gotRG)
		require.Equal(t, wantDisk, gotDisk)
	})

	t.Run("private endpoint", func(t *testing.T) {
		id := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/privateEndpoints/pe-1"
		wantRG := "rg-1"
		wantPE := "pe-1"

		gotRG, gotPE, err := privateEndpointIDParts(id)

		require.NoError(t, err)
		require.Equal(t, wantRG, gotRG)
		require.Equal(t, wantPE, gotPE)
	})

	t.Run("private dns zone group", func(t *testing.T) {
		id := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/privateEndpoints/pe-1/privateDnsZoneGroups/default"
		wantRG := "rg-1"
		wantPE := "pe-1"
		wantGroup := "default"

		gotRG, gotPE, gotGroup, err := privateDnsZoneGroupIDParts(id)

		require.NoError(t, err)
		require.Equal(t, wantRG, gotRG)
		require.Equal(t, wantPE, gotPE)
		require.Equal(t, wantGroup, gotGroup)
	})

	t.Run("case insensitive", func(t *testing.T) {
		id := "/subscriptions/sub-1/resourcegroups/rg-1/providers/Microsoft.Network/privateendpoints/pe-1/privatednszonegroups/default"
		wantRG := "rg-1"
		wantPE := "pe-1"
		wantGroup := "default"

		gotRG, gotPE, gotGroup, err := privateDnsZoneGroupIDParts(id)

		require.NoError(t, err)
		require.Equal(t, wantRG, gotRG)
		require.Equal(t, wantPE, gotPE)
		require.Equal(t, wantGroup, gotGroup)
	})
}

func TestARMIDPartsRejectInvalidIDs(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		gotRG, gotDisk, err := diskIDParts("")

		require.Error(t, err)
		require.Empty(t, gotRG)
		require.Empty(t, gotDisk)
	})

	t.Run("missing leading slash", func(t *testing.T) {
		id := "subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/disks/disk-1"

		gotRG, gotDisk, err := diskIDParts(id)

		require.Error(t, err)
		require.Empty(t, gotRG)
		require.Empty(t, gotDisk)
	})

	t.Run("wrong resource type", func(t *testing.T) {
		id := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/virtualMachines/vm-1"

		gotRG, gotDisk, err := diskIDParts(id)

		require.Error(t, err)
		require.Empty(t, gotRG)
		require.Empty(t, gotDisk)
	})

	t.Run("missing resource group", func(t *testing.T) {
		id := "/subscriptions/sub-1/providers/Microsoft.Compute/disks/disk-1"

		gotRG, gotDisk, err := diskIDParts(id)

		require.Error(t, err)
		require.Empty(t, gotRG)
		require.Empty(t, gotDisk)
	})
}
