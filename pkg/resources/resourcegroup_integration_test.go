// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build integration

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae/pkg/model"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getTestSubscriptionID(t *testing.T) string {
	subID := os.Getenv("AZURE_SUBSCRIPTION_ID")
	if subID == "" {
		t.Skip("AZURE_SUBSCRIPTION_ID environment variable not set")
	}
	return subID
}

// newTestProvisioner creates a ResourceGroup provisioner for testing
func newTestProvisioner(t *testing.T, subscriptionID string) *ResourceGroup {
	cfg := &config.Config{
		SubscriptionId: subscriptionID,
	}

	azureClient, err := client.NewClient(cfg)
	require.NoError(t, err)

	return &ResourceGroup{
		Client: azureClient,
		Config: cfg,
	}
}

// newTestTarget creates a Target for testing
func newTestTarget(subscriptionID string) *model.Target {
	targetConfig := fmt.Appendf(nil, `{"SubscriptionId":"%s"}`, subscriptionID)
	return &model.Target{
		Namespace: "Azure",
		Config:    targetConfig,
	}
}

// deleteResourceGroup deletes a resource group using Azure SDK directly
func deleteResourceGroup(ctx context.Context, rgClient *armresources.ResourceGroupsClient, rgName string) {
	poller, err := rgClient.BeginDelete(ctx, rgName, nil)
	if err != nil {
		log.Printf("Failed to start deletion of resource group %s: %v\n", rgName, err)
		return
	}
	_, err = poller.PollUntilDone(ctx, nil)
	if err != nil {
		log.Printf("Failed to delete resource group %s: %v\n", rgName, err)
	} else {
		log.Printf("Successfully deleted resource group: %s\n", rgName)
	}
}

// stringPtr is defined in common.go

func TestResourceGroup_Create(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	provisioner := newTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	rgName := fmt.Sprintf("formae-test-create-%d", time.Now().Unix())

	// Prepare resource properties
	properties := []byte(`{
		"location": "eastus",
		"tags": {
			"test": "formae",
			"purpose": "integration-test"
		}
	}`)

	req := &resource.CreateRequest{
		Resource: &model.Resource{
			Type:       ResourceTypeResourceGroup,
			Label:      rgName,
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
	assert.Equal(t, resource.OperationStatusSuccess, result.ProgressResult.OperationStatus)
	assert.NotEmpty(t, result.ProgressResult.NativeID)
	assert.Equal(t, ResourceTypeResourceGroup, result.ProgressResult.ResourceType)
	t.Logf("Created resource group with ID: %s", result.ProgressResult.NativeID)

	// Cleanup
	t.Cleanup(func() {
		cred, _ := azidentity.NewDefaultAzureCredential(nil)
		rgClient, _ := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
		deleteResourceGroup(ctx, rgClient, rgName)
	})

	// Verify tags were set correctly
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	rg, err := rgClient.Get(ctx, rgName, nil)
	require.NoError(t, err)
	assert.NotNil(t, rg.Tags)
	assert.Equal(t, "formae", *rg.Tags["test"])
	assert.Equal(t, "integration-test", *rg.Tags["purpose"])
}

func TestResourceGroup_Read(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	provisioner := newTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	rgName := fmt.Sprintf("formae-test-read-%d", time.Now().Unix())

	// Create resource group using Azure SDK directly
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	location := "westus"
	params := armresources.ResourceGroup{
		Location: &location,
		Tags: map[string]*string{
			"test":    stringPtr("formae-read-test"),
			"purpose": stringPtr("read-verification"),
		},
	}

	createdRg, err := rgClient.CreateOrUpdate(ctx, rgName, params, nil)
	require.NoError(t, err)
	t.Logf("Created resource group via Azure SDK: %s", *createdRg.ID)

	t.Cleanup(func() {
		deleteResourceGroup(ctx, rgClient, rgName)
	})

	// Execute Read
	readReq := &resource.ReadRequest{
		NativeID: *createdRg.ID,

		Target: target,
	}

	result, err := provisioner.Read(ctx, readReq)

	// Assert
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, ResourceTypeResourceGroup, result.ResourceType)

	// Verify properties
	var props map[string]interface{}
	err = json.Unmarshal([]byte(result.Properties), &props)
	require.NoError(t, err)
	assert.Equal(t, location, props["location"])

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

func TestResourceGroup_Update(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	provisioner := newTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	rgName := fmt.Sprintf("formae-test-update-%d", time.Now().Unix())

	// Create resource group using Azure SDK with initial tags
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	location := "westus"
	params := armresources.ResourceGroup{
		Location: &location,
		Tags: map[string]*string{
			"environment": stringPtr("dev"),
			"test":        stringPtr("formae-update-test"),
		},
	}

	createResult, err := rgClient.CreateOrUpdate(ctx, rgName, params, nil)
	require.NoError(t, err)
	nativeID := *createResult.ID
	t.Logf("Created resource group: %s", nativeID)

	t.Cleanup(func() {
		deleteResourceGroup(ctx, rgClient, rgName)
	})

	// Prepare updated properties
	updatedProperties := []byte(`{
		"location": "westus",
		"tags": {
			"environment": "prod",
			"test": "formae-update-test",
			"purpose": "testing"
		}
	}`)

	updateReq := &resource.UpdateRequest{
		Resource: &model.Resource{
			Type:       ResourceTypeResourceGroup,
			Label:      rgName,
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
	assert.Equal(t, resource.OperationStatusSuccess, result.ProgressResult.OperationStatus)

	// Verify tags were updated
	updatedRG, err := rgClient.Get(ctx, rgName, nil)
	require.NoError(t, err)
	assert.Equal(t, "prod", *updatedRG.Tags["environment"])
	assert.Equal(t, "formae-update-test", *updatedRG.Tags["test"])
	assert.Equal(t, "testing", *updatedRG.Tags["purpose"])
}

func TestResourceGroup_Delete(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	provisioner := newTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	rgName := fmt.Sprintf("formae-test-delete-%d", time.Now().Unix())

	// Create resource group using Azure SDK directly
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	location := "westus"
	params := armresources.ResourceGroup{
		Location: &location,
	}

	createdRg, err := rgClient.CreateOrUpdate(ctx, rgName, params, nil)
	require.NoError(t, err)
	nativeID := *createdRg.ID
	t.Logf("Created resource group: %s", nativeID)

	// Cleanup in case test fails
	t.Cleanup(func() {
		_, err := rgClient.Get(ctx, rgName, nil)
		if err == nil {
			deleteResourceGroup(ctx, rgClient, rgName)
		}
	})

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
	_, err = rgClient.Get(ctx, rgName, nil)
	assert.Error(t, err, "Resource group should not exist after deletion")
}

func TestResourceGroup_List(t *testing.T) {
	ctx := context.Background()
	subscriptionID := getTestSubscriptionID(t)

	provisioner := newTestProvisioner(t, subscriptionID)
	target := newTestTarget(subscriptionID)

	// Create Azure client for direct resource creation
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	require.NoError(t, err)
	rgClient, err := armresources.NewResourceGroupsClient(subscriptionID, cred, nil)
	require.NoError(t, err)

	// Create 3 resource groups using the Azure client directly
	timestamp := time.Now().Unix()
	testRGNames := []string{
		fmt.Sprintf("formae-test-list-1-%d", timestamp),
		fmt.Sprintf("formae-test-list-2-%d", timestamp),
		fmt.Sprintf("formae-test-list-3-%d", timestamp),
	}

	location := "eastus"
	createdRGNames := make([]string, 0, 3)

	for _, rgName := range testRGNames {
		params := armresources.ResourceGroup{
			Location: &location,
		}

		_, err := rgClient.CreateOrUpdate(ctx, rgName, params, nil)
		require.NoError(t, err, "Failed to create test resource group %s", rgName)
		createdRGNames = append(createdRGNames, rgName)
		t.Logf("Created test resource group: %s", rgName)
	}

	t.Cleanup(func() {
		for _, rgName := range createdRGNames {
			deleteResourceGroup(ctx, rgClient, rgName)
		}
	})

	// Execute List
	listReq := &resource.ListRequest{

		Target: target,
	}

	result, err := provisioner.List(ctx, listReq)
	require.NoError(t, err, "List should not error")
	require.NotNil(t, result, "List result should not be nil")

	// Assert
	assert.NotEmpty(t, result.Resources, "List should return resources")
	t.Logf("List returned %d resource groups", len(result.Resources))

	// Verify all 3 created resource groups are in the results
	foundCount := 0
	for _, rgName := range createdRGNames {
		for _, res := range result.Resources {
			if strings.HasSuffix(res.NativeID, "/resourceGroups/"+rgName) {
				foundCount++
				t.Logf("Found created resource group in results: %s", rgName)
				break
			}
		}
	}

	assert.Equal(t, len(createdRGNames), foundCount,
		"All created resource groups should be found in List results")
}
