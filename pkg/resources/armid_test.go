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

// armExactIDParts exists because "subscriptions" collides with the /subscriptions/{id}
// scope segment that every ARM ID starts with.
func TestArmExactIDParts(t *testing.T) {
	const subID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ServiceBus/namespaces/ns-1/topics/topic-1/subscriptions/sub-a"
	const topicID = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.ServiceBus/namespaces/ns-1/topics/topic-1"

	t.Run("returns one name per level, leaf last", func(t *testing.T) {
		rg, names, err := armExactIDParts(subID, "namespaces", "topics", "subscriptions")
		require.NoError(t, err)
		require.Equal(t, "rg-1", rg)
		require.Equal(t, []string{"ns-1", "topic-1", "sub-a"}, names)
	})

	t.Run("rejects a shorter chain", func(t *testing.T) {
		_, _, err := armExactIDParts(topicID, "namespaces", "topics", "subscriptions")
		require.ErrorContains(t, err, "is not a namespaces/topics/subscriptions")
	})

	t.Run("rejects a longer chain", func(t *testing.T) {
		_, _, err := armExactIDParts(subID, "namespaces", "topics")
		require.ErrorContains(t, err, "is not a namespaces/topics")
	})

	t.Run("rejects a mismatched chain", func(t *testing.T) {
		_, _, err := armExactIDParts(topicID, "namespaces", "queues")
		require.ErrorContains(t, err, "is not a namespaces/queues")
	})

	// The behaviour that motivated the helper: armIDParts happily matches the
	// subscription scope and hands back the subscription GUID for an ID that names
	// no Service Bus subscription at all.
	t.Run("armIDParts matches the subscription scope, armExactIDParts does not", func(t *testing.T) {
		_, names, err := armIDParts(topicID, "subscriptions")
		require.NoError(t, err)
		require.Equal(t, "sub-1", names["subscriptions"])

		_, _, err = armExactIDParts(topicID, "namespaces", "topics", "subscriptions")
		require.Error(t, err)
	})

	t.Run("requires a resource group", func(t *testing.T) {
		_, _, err := armExactIDParts("/subscriptions/sub-1", "namespaces")
		require.Error(t, err)
	})
}
