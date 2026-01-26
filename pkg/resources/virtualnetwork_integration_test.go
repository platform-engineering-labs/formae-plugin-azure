// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/platform-engineering-labs/formae/pkg/model"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newVNetTestProvisioner creates a VirtualNetwork provisioner for testing
func newVNetTestProvisioner(t *testing.T, subscriptionID string) *VirtualNetwork {
	cfg := &config.Config{
		SubscriptionId: subscriptionID,
	}

	azureClient, err := client.NewClient(cfg)
	require.NoError(t, err)

	return &VirtualNetwork{
		Client: azureClient,
		Config: cfg,
	}
}

// createTestResourceGroup creates a resource group for VNet tests
func createTestResourceGroup(t *testing.T, ctx context.Context, subscriptionID, rgName, location string) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	params := armresources.ResourceGroup{
		Location: &location,
	}
	_, err = rgClient.CreateOrUpdate(ctx, rgName, params, nil)
	require.NoError(t, err, "Failed to create test resource group %s", rgName)
	t.Logf("Created test resource group: %s", rgName)
}

// deleteTestResourceGroup deletes a resource group for VNet tests
func deleteTestResourceGroup(ctx context.Context, subscriptionID, rgName string) {
	cred, _ := azidentity.NewDefaultAzureCredential(nil)
	rgClient, _ := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
	deleteResourceGroup(ctx, rgClient, rgName)
}

// deleteVirtualNetwork deletes a VNet using Azure SDK directly
func deleteVirtualNetwork(ctx context.Context, vnetClient *armnetwork.VirtualNetworksClient, rgName, vnetName string) {
	poller, err := vnetClient.BeginDelete(ctx, rgName, vnetName, nil)
	if err != nil {
		return
	}
	_, _ = poller.PollUntilDone(ctx, nil)
}

func TestVirtualNetwork_Create(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	provisioner := newVNetTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	timestamp := time.Now().Unix()
	rgName := fmt.Sprintf("formae-test-vnet-rg-%d", timestamp)
	vnetName := fmt.Sprintf("formae-test-vnet-%d", timestamp)
	location := "eastus"

	// Create resource group first (VNet requires a resource group)
	createTestResourceGroup(t, ctx, subscriptionID, rgName, location)

	// Cleanup resource group (which will also delete the VNet)
	t.Cleanup(func() {
		deleteTestResourceGroup(ctx, subscriptionID, rgName)
	})

	// Prepare VNet properties
	properties := []byte(fmt.Sprintf(`{
		"resourceGroupName": "%s",
		"location": "%s",
		"addressSpace": {
			"addressPrefixes": ["10.0.0.0/16"]
		},
		"tags": {
			"test": "formae",
			"purpose": "integration-test"
		}
	}`, rgName, location))

	req := &resource.CreateRequest{
		Resource: &model.Resource{
			Type:       ResourceTypeVirtualNetwork,
			Label:      vnetName,
			Stack:      "test-stack",
			Properties: properties,
		},
		Target: target,
	}

	// Execute
	result, err := provisioner.Create(ctx, req)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.ProgressResult)
	assert.Equal(t, resource.OperationCreate, result.ProgressResult.Operation)
	// VNet creation is async (LRO), always returns InProgress
	assert.Equal(t, resource.OperationStatusInProgress, result.ProgressResult.OperationStatus)
	assert.NotEmpty(t, result.ProgressResult.NativeID)
	assert.Equal(t, ResourceTypeVirtualNetwork, result.ProgressResult.ResourceType)
	t.Logf("Create started with RequestID: %s", result.ProgressResult.RequestID)

	// Poll Status until operation completes
	maxPolls := 60
	pollInterval := 2 * time.Second
	var finalStatus resource.OperationStatus

	for i := 0; i < maxPolls; i++ {
		statusReq := &resource.StatusRequest{
			RequestID: result.ProgressResult.RequestID,

			Target: target,
		}

		statusResult, err := provisioner.Status(ctx, statusReq)
		require.NoError(t, err)
		require.NotNil(t, statusResult)

		finalStatus = statusResult.ProgressResult.OperationStatus
		t.Logf("Poll %d: Status = %s", i+1, finalStatus)

		if finalStatus == resource.OperationStatusSuccess || finalStatus == resource.OperationStatusFailure {
			break
		}

		time.Sleep(pollInterval)
	}

	assert.Equal(t, resource.OperationStatusSuccess, finalStatus)

	// Verify VNet was created using Azure SDK
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	vnetClient, err := armnetwork.NewVirtualNetworksClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	vnet, err := vnetClient.Get(ctx, rgName, vnetName, nil)
	require.NoError(t, err)
	assert.NotNil(t, vnet.Properties.AddressSpace)
	assert.Contains(t, *vnet.Properties.AddressSpace.AddressPrefixes[0], "10.0.0.0/16")
	assert.Equal(t, "formae", *vnet.Tags["test"])
	assert.Equal(t, "integration-test", *vnet.Tags["purpose"])
}

func TestVirtualNetwork_Read(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	provisioner := newVNetTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	timestamp := time.Now().Unix()
	rgName := fmt.Sprintf("formae-test-vnet-read-rg-%d", timestamp)
	vnetName := fmt.Sprintf("formae-test-vnet-read-%d", timestamp)
	location := "westus"

	// Create resource group first
	createTestResourceGroup(t, ctx, subscriptionID, rgName, location)

	t.Cleanup(func() {
		deleteTestResourceGroup(ctx, subscriptionID, rgName)
	})

	// Create VNet using Azure SDK directly (not provisioner)
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	vnetClient, err := armnetwork.NewVirtualNetworksClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	addressPrefix := "10.1.0.0/16"
	params := armnetwork.VirtualNetwork{
		Location: stringPtr(location),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{&addressPrefix},
			},
		},
		Tags: map[string]*string{
			"test":    stringPtr("formae-read-test"),
			"purpose": stringPtr("read-verification"),
		},
	}

	poller, err := vnetClient.BeginCreateOrUpdate(ctx, rgName, vnetName, params, nil)
	require.NoError(t, err)
	createdVNet, err := poller.PollUntilDone(ctx, nil)
	require.NoError(t, err)
	t.Logf("Created VNet via Azure SDK: %s", *createdVNet.ID)

	// Execute Read
	readReq := &resource.ReadRequest{
		NativeID: *createdVNet.ID,

		Target: target,
	}

	result, err := provisioner.Read(ctx, readReq)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, ResourceTypeVirtualNetwork, result.ResourceType)

	// Verify properties
	var props map[string]interface{}
	err = json.Unmarshal([]byte(result.Properties), &props)
	require.NoError(t, err)

	assert.Equal(t, location, props["location"])
	assert.Equal(t, vnetName, props["name"])
	assert.Equal(t, rgName, props["resourceGroupName"])

	// Verify addressSpace
	addressSpace, ok := props["addressSpace"].(map[string]interface{})
	require.True(t, ok, "addressSpace should be a map")
	prefixes, ok := addressSpace["addressPrefixes"].([]interface{})
	require.True(t, ok, "addressPrefixes should be an array")
	assert.Contains(t, prefixes, "10.1.0.0/16")

	// Verify tags
	tags := model.GetTagsFromProperties([]byte(result.Properties))
	assert.Len(t, tags, 2)
	tagMap := make(map[string]string)
	for _, tag := range tags {
		tagMap[tag.Key] = tag.Value
	}
	assert.Equal(t, "formae-read-test", tagMap["test"])
	assert.Equal(t, "read-verification", tagMap["purpose"])
}

func TestVirtualNetwork_Update(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	provisioner := newVNetTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	timestamp := time.Now().Unix()
	rgName := fmt.Sprintf("formae-test-vnet-update-rg-%d", timestamp)
	vnetName := fmt.Sprintf("formae-test-vnet-update-%d", timestamp)
	location := "eastus"

	// Create resource group first
	createTestResourceGroup(t, ctx, subscriptionID, rgName, location)

	t.Cleanup(func() {
		deleteTestResourceGroup(ctx, subscriptionID, rgName)
	})

	// Create VNet using Azure SDK with initial tags
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	vnetClient, err := armnetwork.NewVirtualNetworksClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	addressPrefix := "10.2.0.0/16"
	params := armnetwork.VirtualNetwork{
		Location: stringPtr(location),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{&addressPrefix},
			},
		},
		Tags: map[string]*string{
			"environment": stringPtr("dev"),
			"test":        stringPtr("formae-update-test"),
		},
	}

	poller, err := vnetClient.BeginCreateOrUpdate(ctx, rgName, vnetName, params, nil)
	require.NoError(t, err)
	createdVNet, err := poller.PollUntilDone(ctx, nil)
	require.NoError(t, err)
	nativeID := *createdVNet.ID
	t.Logf("Created VNet: %s", nativeID)

	// Prepare updated properties (change tags)
	updatedProperties := []byte(fmt.Sprintf(`{
		"resourceGroupName": "%s",
		"location": "%s",
		"addressSpace": {
			"addressPrefixes": ["10.2.0.0/16"]
		},
		"tags": {
			"environment": "prod",
			"test": "formae-update-test",
			"purpose": "testing"
		}
	}`, rgName, location))

	updateReq := &resource.UpdateRequest{
		Resource: &model.Resource{
			Type:       ResourceTypeVirtualNetwork,
			Label:      vnetName,
			Stack:      "test-stack",
			Properties: updatedProperties,
		},
		Target:   target,
		NativeID: &nativeID,
	}

	// Execute Update
	result, err := provisioner.Update(ctx, updateReq)

	// Assert: Update can be sync or async depending on Azure's behavior
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.ProgressResult)
	assert.Equal(t, resource.OperationUpdate, result.ProgressResult.Operation)

	var finalStatus resource.OperationStatus

	// Check if operation completed synchronously
	if result.ProgressResult.OperationStatus == resource.OperationStatusSuccess {
		t.Logf("Update completed synchronously")
		finalStatus = resource.OperationStatusSuccess
	} else if result.ProgressResult.OperationStatus == resource.OperationStatusInProgress {
		// Async operation - poll for completion
		assert.NotEmpty(t, result.ProgressResult.RequestID, "RequestID should be present for async operations")
		t.Logf("Update started async with RequestID: %s", result.ProgressResult.RequestID)

		maxPolls := 60
		pollInterval := 2 * time.Second

		for i := 0; i < maxPolls; i++ {
			statusReq := &resource.StatusRequest{
				RequestID: result.ProgressResult.RequestID,

				Target: target,
			}

			statusResult, err := provisioner.Status(ctx, statusReq)
			require.NoError(t, err)
			require.NotNil(t, statusResult)

			finalStatus = statusResult.ProgressResult.OperationStatus
			t.Logf("Poll %d: Status = %s", i+1, finalStatus)

			if finalStatus == resource.OperationStatusSuccess || finalStatus == resource.OperationStatusFailure {
				break
			}

			time.Sleep(pollInterval)
		}
	} else {
		t.Fatalf("Unexpected initial status: %s", result.ProgressResult.OperationStatus)
	}

	assert.Equal(t, resource.OperationStatusSuccess, finalStatus)

	// Verify tags were updated
	updatedVNet, err := vnetClient.Get(ctx, rgName, vnetName, nil)
	require.NoError(t, err)
	assert.Equal(t, "prod", *updatedVNet.Tags["environment"])
	assert.Equal(t, "formae-update-test", *updatedVNet.Tags["test"])
	assert.Equal(t, "testing", *updatedVNet.Tags["purpose"])
}

func TestVirtualNetwork_Delete(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	provisioner := newVNetTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	timestamp := time.Now().Unix()
	rgName := fmt.Sprintf("formae-test-vnet-delete-rg-%d", timestamp)
	vnetName := fmt.Sprintf("formae-test-vnet-delete-%d", timestamp)
	location := "westus"

	// Create resource group first
	createTestResourceGroup(t, ctx, subscriptionID, rgName, location)

	t.Cleanup(func() {
		// Cleanup resource group in case test fails
		deleteTestResourceGroup(ctx, subscriptionID, rgName)
	})

	// Create VNet using Azure SDK directly
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	vnetClient, err := armnetwork.NewVirtualNetworksClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	addressPrefix := "10.3.0.0/16"
	params := armnetwork.VirtualNetwork{
		Location: stringPtr(location),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{&addressPrefix},
			},
		},
	}

	poller, err := vnetClient.BeginCreateOrUpdate(ctx, rgName, vnetName, params, nil)
	require.NoError(t, err)
	createdVNet, err := poller.PollUntilDone(ctx, nil)
	require.NoError(t, err)
	nativeID := *createdVNet.ID
	t.Logf("Created VNet: %s", nativeID)

	// Execute Delete
	deleteReq := &resource.DeleteRequest{
		NativeID: &nativeID,

		Target: target,
	}

	deleteResult, err := provisioner.Delete(ctx, deleteReq)

	// Assert: VNet deletion is async (LRO)
	require.NoError(t, err)
	require.NotNil(t, deleteResult)
	require.NotNil(t, deleteResult.ProgressResult)
	assert.Equal(t, resource.OperationDelete, deleteResult.ProgressResult.Operation)
	assert.Equal(t, resource.OperationStatusInProgress, deleteResult.ProgressResult.OperationStatus)
	assert.NotEmpty(t, deleteResult.ProgressResult.RequestID)
	t.Logf("Delete started with RequestID: %s", deleteResult.ProgressResult.RequestID)

	// Poll Status until operation completes
	maxPolls := 60
	pollInterval := 2 * time.Second
	var finalStatus resource.OperationStatus
	var statusResult *resource.StatusResult

	for i := 0; i < maxPolls; i++ {
		statusReq := &resource.StatusRequest{
			RequestID: deleteResult.ProgressResult.RequestID,

			Target: target,
		}

		statusResult, err = provisioner.Status(ctx, statusReq)
		require.NoError(t, err)
		require.NotNil(t, statusResult)

		finalStatus = statusResult.ProgressResult.OperationStatus
		t.Logf("Poll %d: Status = %s", i+1, finalStatus)

		if finalStatus == resource.OperationStatusSuccess || finalStatus == resource.OperationStatusFailure {
			break
		}

		time.Sleep(pollInterval)
	}

	// Delete should complete successfully
	assert.Equal(t, resource.OperationStatusSuccess, finalStatus)

	// Verify resource is actually deleted
	_, err = vnetClient.Get(ctx, rgName, vnetName, nil)
	assert.Error(t, err, "VNet should not exist after deletion")
}

func TestVirtualNetwork_List(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	provisioner := newVNetTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	timestamp := time.Now().Unix()
	rgName := fmt.Sprintf("formae-test-vnet-list-rg-%d", timestamp)
	vnetName1 := fmt.Sprintf("formae-test-vnet-list-1-%d", timestamp)
	vnetName2 := fmt.Sprintf("formae-test-vnet-list-2-%d", timestamp)
	location := "eastus"

	// Create resource group first
	createTestResourceGroup(t, ctx, subscriptionID, rgName, location)

	t.Cleanup(func() {
		deleteTestResourceGroup(ctx, subscriptionID, rgName)
	})

	// Create two VNets using Azure SDK directly
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	vnetClient, err := armnetwork.NewVirtualNetworksClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	// Create first VNet
	addressPrefix1 := "10.0.0.0/16"
	params1 := armnetwork.VirtualNetwork{
		Location: stringPtr(location),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{&addressPrefix1},
			},
		},
		Tags: map[string]*string{
			"test": stringPtr("formae-list-test-1"),
		},
	}
	poller1, err := vnetClient.BeginCreateOrUpdate(ctx, rgName, vnetName1, params1, nil)
	require.NoError(t, err)
	createdVNet1, err := poller1.PollUntilDone(ctx, nil)
	require.NoError(t, err)
	t.Logf("Created VNet 1: %s", *createdVNet1.ID)

	// Create second VNet
	addressPrefix2 := "10.1.0.0/16"
	params2 := armnetwork.VirtualNetwork{
		Location: stringPtr(location),
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{&addressPrefix2},
			},
		},
		Tags: map[string]*string{
			"test": stringPtr("formae-list-test-2"),
		},
	}
	poller2, err := vnetClient.BeginCreateOrUpdate(ctx, rgName, vnetName2, params2, nil)
	require.NoError(t, err)
	createdVNet2, err := poller2.PollUntilDone(ctx, nil)
	require.NoError(t, err)
	t.Logf("Created VNet 2: %s", *createdVNet2.ID)

	// Execute List with resourceGroupName in AdditionalProperties
	listReq := &resource.ListRequest{

		Target: target,
		AdditionalProperties: map[string]string{
			"resourceGroupName": rgName,
		},
	}

	result, err := provisioner.List(ctx, listReq)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, ResourceTypeVirtualNetwork, result.ResourceType)
	assert.GreaterOrEqual(t, len(result.Resources), 2, "Should list at least 2 VNets")

	// Verify both VNets are in the result
	foundVNet1 := false
	foundVNet2 := false
	for _, res := range result.Resources {
		if res.NativeID == *createdVNet1.ID {
			foundVNet1 = true
			// Verify properties
			var props map[string]interface{}
			err := json.Unmarshal([]byte(res.Properties), &props)
			require.NoError(t, err)
			assert.Equal(t, location, props["location"])
			assert.Equal(t, vnetName1, props["name"])
		}
		if res.NativeID == *createdVNet2.ID {
			foundVNet2 = true
		}
	}
	assert.True(t, foundVNet1, "VNet 1 should be in list result")
	assert.True(t, foundVNet2, "VNet 2 should be in list result")
}
