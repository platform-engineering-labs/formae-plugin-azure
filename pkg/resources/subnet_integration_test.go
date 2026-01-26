// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
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

// newSubnetTestProvisioner creates a Subnet provisioner for testing
func newSubnetTestProvisioner(t *testing.T, subscriptionID string) *Subnet {
	cfg := &config.Config{
		SubscriptionId: subscriptionID,
	}

	azureClient, err := client.NewClient(cfg)
	require.NoError(t, err)

	return &Subnet{
		Client: azureClient,
		Config: cfg,
	}
}

// createTestVNet creates a VNet for subnet tests and returns (vnetName, cleanup func)
func createTestVNet(t *testing.T, ctx context.Context, subscriptionID, rgName string) (string, func()) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	vnetClient, err := armnetwork.NewVirtualNetworksClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	vnetName := fmt.Sprintf("formae-test-vnet-%d", time.Now().Unix())
	location := "eastus"

	params := armnetwork.VirtualNetwork{
		Location: &location,
		Properties: &armnetwork.VirtualNetworkPropertiesFormat{
			AddressSpace: &armnetwork.AddressSpace{
				AddressPrefixes: []*string{stringPtr("10.0.0.0/16")},
			},
		},
	}

	poller, err := vnetClient.BeginCreateOrUpdate(ctx, rgName, vnetName, params, nil)
	require.NoError(t, err)

	_, err = poller.PollUntilDone(ctx, nil)
	require.NoError(t, err)

	t.Logf("Created test VNet: %s", vnetName)

	cleanup := func() {
		t.Logf("Deleting test VNet: %s", vnetName)
		delPoller, err := vnetClient.BeginDelete(ctx, rgName, vnetName, nil)
		if err != nil {
			t.Logf("Warning: failed to start VNet deletion: %v", err)
			return
		}
		_, err = delPoller.PollUntilDone(ctx, nil)
		if err != nil {
			t.Logf("Warning: failed to delete VNet: %v", err)
		}
	}

	return vnetName, cleanup
}

// createSubnetTestRG creates a resource group for subnet tests and returns (rgName, cleanup func)
func createSubnetTestRG(t *testing.T, ctx context.Context, subscriptionID string) (string, func()) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)

	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	rgName := fmt.Sprintf("formae-test-subnet-rg-%d", time.Now().Unix())
	location := "eastus"

	params := armresources.ResourceGroup{
		Location: &location,
	}

	_, err = rgClient.CreateOrUpdate(ctx, rgName, params, nil)
	require.NoError(t, err)

	t.Logf("Created test resource group: %s", rgName)

	cleanup := func() {
		t.Logf("Deleting test resource group: %s", rgName)
		delPoller, err := rgClient.BeginDelete(ctx, rgName, nil)
		if err != nil {
			t.Logf("Warning: failed to start RG deletion: %v", err)
			return
		}
		_, err = delPoller.PollUntilDone(ctx, nil)
		if err != nil {
			t.Logf("Warning: failed to delete RG: %v", err)
		}
	}

	return rgName, cleanup
}

func TestSubnet_Create(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	// Create test infrastructure: RG -> VNet -> Subnet
	rgName, cleanupRG := createSubnetTestRG(t, ctx, subscriptionID)
	t.Cleanup(cleanupRG)

	vnetName, cleanupVNet := createTestVNet(t, ctx, subscriptionID, rgName)
	t.Cleanup(cleanupVNet)

	provisioner := newSubnetTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	subnetName := fmt.Sprintf("formae-test-subnet-%d", time.Now().Unix())

	// Prepare resource properties
	properties := []byte(fmt.Sprintf(`{
		"name": "%s",
		"resourceGroupName": "%s",
		"virtualNetworkName": "%s",
		"addressPrefix": "10.0.1.0/24"
	}`, subnetName, rgName, vnetName))

	req := &resource.CreateRequest{
		Resource: &model.Resource{
			Type:       ResourceTypeSubnet,
			Label:      subnetName,
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

	// Handle async operation if needed
	if result.ProgressResult.OperationStatus == resource.OperationStatusInProgress {
		t.Logf("Create returned InProgress, polling status...")
		maxPolls := 60
		pollInterval := 500 * time.Millisecond

		for i := 0; i < maxPolls; i++ {
			statusReq := &resource.StatusRequest{
				RequestID: result.ProgressResult.RequestID,

				Target: target,
			}

			statusResult, err := provisioner.Status(ctx, statusReq)
			require.NoError(t, err)
			require.NotNil(t, statusResult)

			if statusResult.ProgressResult.OperationStatus == resource.OperationStatusSuccess {
				result.ProgressResult = statusResult.ProgressResult
				break
			}
			if statusResult.ProgressResult.OperationStatus == resource.OperationStatusFailure {
				t.Fatalf("Create operation failed: %s", statusResult.ProgressResult.ErrorCode)
			}

			time.Sleep(pollInterval)
		}
	}

	assert.Equal(t, resource.OperationStatusSuccess, result.ProgressResult.OperationStatus)
	assert.NotEmpty(t, result.ProgressResult.NativeID)
	assert.Equal(t, ResourceTypeSubnet, result.ProgressResult.ResourceType)
	t.Logf("Created subnet with ID: %s", result.ProgressResult.NativeID)

	// Cleanup: Delete the subnet
	t.Cleanup(func() {
		cred, _ := azidentity.NewDefaultAzureCredential(nil)
		subnetClient, _ := armnetwork.NewSubnetsClient(subscriptionID, cred, nil)
		delPoller, err := subnetClient.BeginDelete(ctx, rgName, vnetName, subnetName, nil)
		if err != nil {
			t.Logf("Warning: failed to start subnet deletion: %v", err)
			return
		}
		_, err = delPoller.PollUntilDone(ctx, nil)
		if err != nil {
			t.Logf("Warning: failed to delete subnet: %v", err)
		}
	})

	// Verify subnet was created correctly using Azure SDK
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	subnetClient, err := armnetwork.NewSubnetsClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	subnet, err := subnetClient.Get(ctx, rgName, vnetName, subnetName, nil)
	require.NoError(t, err)
	assert.NotNil(t, subnet.Properties)
	assert.Equal(t, "10.0.1.0/24", *subnet.Properties.AddressPrefix)
}

func TestSubnet_Read(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	// Create test infrastructure: RG -> VNet -> Subnet (via Azure SDK directly)
	rgName, cleanupRG := createSubnetTestRG(t, ctx, subscriptionID)
	t.Cleanup(cleanupRG)

	vnetName, cleanupVNet := createTestVNet(t, ctx, subscriptionID, rgName)
	t.Cleanup(cleanupVNet)

	// Create subnet using Azure SDK directly
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	subnetClient, err := armnetwork.NewSubnetsClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	subnetName := fmt.Sprintf("formae-test-subnet-read-%d", time.Now().Unix())
	addressPrefix := "10.0.2.0/24"

	params := armnetwork.Subnet{
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: &addressPrefix,
		},
	}

	poller, err := subnetClient.BeginCreateOrUpdate(ctx, rgName, vnetName, subnetName, params, nil)
	require.NoError(t, err)
	createdSubnet, err := poller.PollUntilDone(ctx, nil)
	require.NoError(t, err)
	t.Logf("Created subnet via Azure SDK: %s", *createdSubnet.ID)

	provisioner := newSubnetTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	// Execute Read
	readReq := &resource.ReadRequest{
		NativeID: *createdSubnet.ID,

		Target: target,
	}

	result, err := provisioner.Read(ctx, readReq)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, ResourceTypeSubnet, result.ResourceType)

	// Verify properties
	var props map[string]interface{}
	err = json.Unmarshal([]byte(result.Properties), &props)
	require.NoError(t, err)
	assert.Equal(t, subnetName, props["name"])
	assert.Equal(t, rgName, props["resourceGroupName"])
	assert.Equal(t, vnetName, props["virtualNetworkName"])
	assert.Equal(t, addressPrefix, props["addressPrefix"])
}

func TestSubnet_Update(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	// Create test infrastructure: RG -> VNet -> Subnet (via Azure SDK directly)
	rgName, cleanupRG := createSubnetTestRG(t, ctx, subscriptionID)
	t.Cleanup(cleanupRG)

	vnetName, cleanupVNet := createTestVNet(t, ctx, subscriptionID, rgName)
	t.Cleanup(cleanupVNet)

	// Create subnet using Azure SDK directly with initial addressPrefix
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	subnetClient, err := armnetwork.NewSubnetsClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	subnetName := fmt.Sprintf("formae-test-subnet-update-%d", time.Now().Unix())
	initialAddressPrefix := "10.0.3.0/24"

	params := armnetwork.Subnet{
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: &initialAddressPrefix,
		},
	}

	poller, err := subnetClient.BeginCreateOrUpdate(ctx, rgName, vnetName, subnetName, params, nil)
	require.NoError(t, err)
	createdSubnet, err := poller.PollUntilDone(ctx, nil)
	require.NoError(t, err)
	nativeID := *createdSubnet.ID
	t.Logf("Created subnet: %s", nativeID)

	provisioner := newSubnetTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	// Prepare updated properties (change addressPrefix)
	updatedAddressPrefix := "10.0.4.0/24"
	updatedProperties := []byte(fmt.Sprintf(`{
		"name": "%s",
		"resourceGroupName": "%s",
		"virtualNetworkName": "%s",
		"addressPrefix": "%s"
	}`, subnetName, rgName, vnetName, updatedAddressPrefix))

	updateReq := &resource.UpdateRequest{
		Resource: &model.Resource{
			Type:       ResourceTypeSubnet,
			Label:      subnetName,
			Stack:      "test-stack",
			Properties: updatedProperties,
		},
		Target:   target,
		NativeID: &nativeID,
	}

	// Execute Update
	result, err := provisioner.Update(ctx, updateReq)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.ProgressResult)
	assert.Equal(t, resource.OperationUpdate, result.ProgressResult.Operation)

	// Handle async operation if needed
	if result.ProgressResult.OperationStatus == resource.OperationStatusInProgress {
		t.Logf("Update returned InProgress, polling status...")
		maxPolls := 60
		pollInterval := 500 * time.Millisecond

		for i := 0; i < maxPolls; i++ {
			statusReq := &resource.StatusRequest{
				RequestID: result.ProgressResult.RequestID,

				Target: target,
			}

			statusResult, err := provisioner.Status(ctx, statusReq)
			require.NoError(t, err)
			require.NotNil(t, statusResult)

			if statusResult.ProgressResult.OperationStatus == resource.OperationStatusSuccess {
				result.ProgressResult = statusResult.ProgressResult
				break
			}
			if statusResult.ProgressResult.OperationStatus == resource.OperationStatusFailure {
				t.Fatalf("Update operation failed: %s", statusResult.ProgressResult.ErrorCode)
			}

			time.Sleep(pollInterval)
		}
	}

	assert.Equal(t, resource.OperationStatusSuccess, result.ProgressResult.OperationStatus)

	// Verify addressPrefix was updated
	updatedSubnet, err := subnetClient.Get(ctx, rgName, vnetName, subnetName, nil)
	require.NoError(t, err)
	assert.Equal(t, updatedAddressPrefix, *updatedSubnet.Properties.AddressPrefix)
}

func TestSubnet_Delete(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	// Create test infrastructure: RG -> VNet -> Subnet (via Azure SDK directly)
	rgName, cleanupRG := createSubnetTestRG(t, ctx, subscriptionID)
	t.Cleanup(cleanupRG)

	vnetName, cleanupVNet := createTestVNet(t, ctx, subscriptionID, rgName)
	t.Cleanup(cleanupVNet)

	// Create subnet using Azure SDK directly
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	subnetClient, err := armnetwork.NewSubnetsClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	subnetName := fmt.Sprintf("formae-test-subnet-delete-%d", time.Now().Unix())
	addressPrefix := "10.0.5.0/24"

	params := armnetwork.Subnet{
		Properties: &armnetwork.SubnetPropertiesFormat{
			AddressPrefix: &addressPrefix,
		},
	}

	poller, err := subnetClient.BeginCreateOrUpdate(ctx, rgName, vnetName, subnetName, params, nil)
	require.NoError(t, err)
	createdSubnet, err := poller.PollUntilDone(ctx, nil)
	require.NoError(t, err)
	nativeID := *createdSubnet.ID
	t.Logf("Created subnet: %s", nativeID)

	provisioner := newSubnetTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	// Execute Delete
	deleteReq := &resource.DeleteRequest{
		NativeID: &nativeID,

		Target: target,
	}

	deleteResult, err := provisioner.Delete(ctx, deleteReq)

	// Assert: Expect InProgress status (async operation)
	require.NoError(t, err)
	require.NotNil(t, deleteResult)
	require.NotNil(t, deleteResult.ProgressResult)
	assert.Equal(t, resource.OperationDelete, deleteResult.ProgressResult.Operation)
	assert.Equal(t, resource.OperationStatusInProgress, deleteResult.ProgressResult.OperationStatus)
	assert.NotEmpty(t, deleteResult.ProgressResult.RequestID)
	t.Logf("Delete started with RequestID: %s", deleteResult.ProgressResult.RequestID)

	// Poll Status until operation completes
	maxPolls := 60
	pollInterval := 500 * time.Millisecond
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
		t.Logf("Poll %d: Status = %s, ErrorCode = %s", i+1, finalStatus, statusResult.ProgressResult.ErrorCode)

		if finalStatus == resource.OperationStatusSuccess || finalStatus == resource.OperationStatusFailure {
			break
		}

		time.Sleep(pollInterval)
	}

	// Delete should complete successfully
	assert.Equal(t, resource.OperationStatusSuccess, finalStatus)

	// Verify resource is actually deleted
	_, err = subnetClient.Get(ctx, rgName, vnetName, subnetName, nil)
	assert.Error(t, err, "Subnet should not exist after deletion")
}

func TestSubnet_List(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	// Create test infrastructure: RG -> VNet -> multiple Subnets
	rgName, cleanupRG := createSubnetTestRG(t, ctx, subscriptionID)
	t.Cleanup(cleanupRG)

	vnetName, cleanupVNet := createTestVNet(t, ctx, subscriptionID, rgName)
	t.Cleanup(cleanupVNet)

	// Create Azure client for direct subnet creation
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	subnetClient, err := armnetwork.NewSubnetsClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	// Create 3 subnets using Azure SDK directly
	timestamp := time.Now().Unix()
	testSubnetNames := []string{
		fmt.Sprintf("formae-test-subnet-list-1-%d", timestamp),
		fmt.Sprintf("formae-test-subnet-list-2-%d", timestamp),
		fmt.Sprintf("formae-test-subnet-list-3-%d", timestamp),
	}

	// Each subnet needs a different address prefix
	addressPrefixes := []string{"10.0.10.0/24", "10.0.11.0/24", "10.0.12.0/24"}
	createdSubnetNames := make([]string, 0, 3)

	for i, subnetName := range testSubnetNames {
		params := armnetwork.Subnet{
			Properties: &armnetwork.SubnetPropertiesFormat{
				AddressPrefix: &addressPrefixes[i],
			},
		}

		poller, err := subnetClient.BeginCreateOrUpdate(ctx, rgName, vnetName, subnetName, params, nil)
		require.NoError(t, err, "Failed to start subnet creation for %s", subnetName)
		_, err = poller.PollUntilDone(ctx, nil)
		require.NoError(t, err, "Failed to create test subnet %s", subnetName)
		createdSubnetNames = append(createdSubnetNames, subnetName)
		t.Logf("Created test subnet: %s", subnetName)
	}

	provisioner := newSubnetTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	// Execute List (requires resourceGroupName and virtualNetworkName in AdditionalProperties)
	listReq := &resource.ListRequest{

		Target: target,
		AdditionalProperties: map[string]string{
			"resourceGroupName":  rgName,
			"virtualNetworkName": vnetName,
		},
	}

	result, err := provisioner.List(ctx, listReq)
	require.NoError(t, err, "List should not error")
	require.NotNil(t, result, "List result should not be nil")

	// Assert
	assert.NotEmpty(t, result.Resources, "List should return resources")
	t.Logf("List returned %d subnets", len(result.Resources))

	// Verify all 3 created subnets are in the results
	foundCount := 0
	for _, subnetName := range createdSubnetNames {
		for _, res := range result.Resources {
			if strings.Contains(res.NativeID, "/subnets/"+subnetName) {
				foundCount++
				t.Logf("Found created subnet in results: %s", subnetName)
				break
			}
		}
	}

	assert.Equal(t, len(createdSubnetNames), foundCount,
		"All created subnets should be found in List results")
}
