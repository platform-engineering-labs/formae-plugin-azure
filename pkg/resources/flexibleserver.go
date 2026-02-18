// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/postgresql/armpostgresqlflexibleservers/v4"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeFlexibleServer = "Azure::DBforPostgreSQL::FlexibleServer"

func init() {
	registry.Register(ResourceTypeFlexibleServer, func(client *client.Client, cfg *config.Config) prov.Provisioner {
		return &FlexibleServer{client, cfg}
	})
}

// FlexibleServer is the provisioner for Azure Database for PostgreSQL Flexible Server.
type FlexibleServer struct {
	Client *client.Client
	Config *config.Config
}

// buildPropertiesFromResult extracts properties from a FlexibleServer Azure response.
func (f *FlexibleServer) buildPropertiesFromResult(server *armpostgresqlflexibleservers.Server) map[string]interface{} {
	props := make(map[string]interface{})

	// createOnly properties
	if server.ID != nil {
		parts := splitResourceID(*server.ID)
		props["resourceGroupName"] = parts["resourcegroups"]
	}

	if server.Name != nil {
		props["name"] = *server.Name
	}

	// Normalize location to "name" format (lowercase, no spaces)
	// Azure returns "West US 2" for FlexibleServer but "westus2" for ResourceGroup
	if server.Location != nil {
		props["location"] = strings.ToLower(strings.ReplaceAll(*server.Location, " ", ""))
	}

	// SKU
	if server.SKU != nil {
		sku := make(map[string]interface{})
		if server.SKU.Name != nil {
			sku["name"] = *server.SKU.Name
		}
		if server.SKU.Tier != nil {
			sku["tier"] = string(*server.SKU.Tier)
		}
		props["sku"] = sku
	}

	// Server properties
	if server.Properties != nil {
		if server.Properties.Version != nil {
			props["version"] = string(*server.Properties.Version)
		}

		if server.Properties.AdministratorLogin != nil {
			props["administratorLogin"] = *server.Properties.AdministratorLogin
		}

		if server.Properties.AvailabilityZone != nil {
			props["availabilityZone"] = *server.Properties.AvailabilityZone
		}

		// Storage
		if server.Properties.Storage != nil {
			storage := make(map[string]interface{})
			if server.Properties.Storage.StorageSizeGB != nil {
				storage["storageSizeGB"] = *server.Properties.Storage.StorageSizeGB
			}
			if server.Properties.Storage.AutoGrow != nil {
				storage["autoGrow"] = string(*server.Properties.Storage.AutoGrow)
			}
			if server.Properties.Storage.Tier != nil {
				storage["tier"] = string(*server.Properties.Storage.Tier)
			}
			if server.Properties.Storage.Iops != nil {
				storage["iops"] = *server.Properties.Storage.Iops
			}
			if server.Properties.Storage.Throughput != nil {
				storage["throughput"] = *server.Properties.Storage.Throughput
			}
			if len(storage) > 0 {
				props["storage"] = storage
			}
		}

		// Backup
		if server.Properties.Backup != nil {
			backup := make(map[string]interface{})
			if server.Properties.Backup.BackupRetentionDays != nil {
				backup["backupRetentionDays"] = *server.Properties.Backup.BackupRetentionDays
			}
			if server.Properties.Backup.GeoRedundantBackup != nil {
				backup["geoRedundantBackup"] = string(*server.Properties.Backup.GeoRedundantBackup)
			}
			if len(backup) > 0 {
				props["backup"] = backup
			}
		}

		// High Availability
		if server.Properties.HighAvailability != nil {
			ha := make(map[string]interface{})
			if server.Properties.HighAvailability.Mode != nil {
				ha["mode"] = string(*server.Properties.HighAvailability.Mode)
			}
			if server.Properties.HighAvailability.StandbyAvailabilityZone != nil {
				ha["standbyAvailabilityZone"] = *server.Properties.HighAvailability.StandbyAvailabilityZone
			}
			if len(ha) > 0 {
				props["highAvailability"] = ha
			}
		}

		// Network
		// Only include network block if delegatedSubnetResourceId or privateDnsZoneArmResourceId
		// are set. Azure always returns publicNetworkAccess as a default, but including network
		// with only that field causes PKL extract rendering errors for the undefined optional fields.
		if server.Properties.Network != nil &&
			(server.Properties.Network.DelegatedSubnetResourceID != nil || server.Properties.Network.PrivateDNSZoneArmResourceID != nil) {
			network := make(map[string]interface{})
			if server.Properties.Network.DelegatedSubnetResourceID != nil {
				network["delegatedSubnetResourceId"] = *server.Properties.Network.DelegatedSubnetResourceID
			}
			if server.Properties.Network.PrivateDNSZoneArmResourceID != nil {
				network["privateDnsZoneArmResourceId"] = *server.Properties.Network.PrivateDNSZoneArmResourceID
			}
			if server.Properties.Network.PublicNetworkAccess != nil {
				network["publicNetworkAccess"] = string(*server.Properties.Network.PublicNetworkAccess)
			}
			if len(network) > 0 {
				props["network"] = network
			}
		}

		// Maintenance Window
		if server.Properties.MaintenanceWindow != nil {
			mw := make(map[string]interface{})
			if server.Properties.MaintenanceWindow.CustomWindow != nil {
				mw["customWindow"] = *server.Properties.MaintenanceWindow.CustomWindow
			}
			if server.Properties.MaintenanceWindow.DayOfWeek != nil {
				mw["dayOfWeek"] = *server.Properties.MaintenanceWindow.DayOfWeek
			}
			if server.Properties.MaintenanceWindow.StartHour != nil {
				mw["startHour"] = *server.Properties.MaintenanceWindow.StartHour
			}
			if server.Properties.MaintenanceWindow.StartMinute != nil {
				mw["startMinute"] = *server.Properties.MaintenanceWindow.StartMinute
			}
			if len(mw) > 0 {
				props["maintenanceWindow"] = mw
			}
		}

		// Auth Config
		if server.Properties.AuthConfig != nil {
			auth := make(map[string]interface{})
			if server.Properties.AuthConfig.ActiveDirectoryAuth != nil {
				auth["activeDirectoryAuth"] = string(*server.Properties.AuthConfig.ActiveDirectoryAuth)
			}
			if server.Properties.AuthConfig.PasswordAuth != nil {
				auth["passwordAuth"] = string(*server.Properties.AuthConfig.PasswordAuth)
			}
			if server.Properties.AuthConfig.TenantID != nil {
				auth["tenantId"] = *server.Properties.AuthConfig.TenantID
			}
			if len(auth) > 0 {
				props["authConfig"] = auth
			}
		}

		// Read-only properties
		if server.Properties.FullyQualifiedDomainName != nil {
			props["fullyQualifiedDomainName"] = *server.Properties.FullyQualifiedDomainName
		}
		if server.Properties.State != nil {
			props["state"] = string(*server.Properties.State)
		}
	}

	// Tags
	if tags := azureTagsToFormaeTags(server.Tags); tags != nil {
		props["Tags"] = tags
	}

	// ID
	if server.ID != nil {
		props["id"] = *server.ID
	}

	return props
}

func (f *FlexibleServer) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	// Parse properties JSON
	var props map[string]interface{}
	if err := json.Unmarshal(request.Properties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// Extract required properties
	rgName, ok := props["resourceGroupName"].(string)
	if !ok || rgName == "" {
		return nil, fmt.Errorf("resourceGroupName is required")
	}

	location, ok := props["location"].(string)
	if !ok || location == "" {
		return nil, fmt.Errorf("location is required")
	}

	serverName, ok := props["name"].(string)
	if !ok || serverName == "" {
		serverName = request.Label
	}

	version, ok := props["version"].(string)
	if !ok || version == "" {
		return nil, fmt.Errorf("version is required")
	}

	adminLogin, ok := props["administratorLogin"].(string)
	if !ok || adminLogin == "" {
		return nil, fmt.Errorf("administratorLogin is required")
	}

	adminPassword, ok := props["administratorLoginPassword"].(string)
	if !ok || adminPassword == "" {
		return nil, fmt.Errorf("administratorLoginPassword is required")
	}

	// Extract SKU
	skuMap, ok := props["sku"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("sku is required")
	}
	skuName, _ := skuMap["name"].(string)
	skuTierStr, _ := skuMap["tier"].(string)
	if skuName == "" || skuTierStr == "" {
		return nil, fmt.Errorf("sku.name and sku.tier are required")
	}

	// Build Server parameters
	serverVersion := armpostgresqlflexibleservers.ServerVersion(version)
	skuTier := armpostgresqlflexibleservers.SKUTier(skuTierStr)

	params := armpostgresqlflexibleservers.Server{
		Location: to.Ptr(location),
		SKU: &armpostgresqlflexibleservers.SKU{
			Name: to.Ptr(skuName),
			Tier: &skuTier,
		},
		Properties: &armpostgresqlflexibleservers.ServerProperties{
			Version:                    &serverVersion,
			AdministratorLogin:         to.Ptr(adminLogin),
			AdministratorLoginPassword: to.Ptr(adminPassword),
			CreateMode:                 to.Ptr(armpostgresqlflexibleservers.CreateModeDefault),
		},
	}

	// Optional: availability zone
	if az, ok := props["availabilityZone"].(string); ok && az != "" {
		params.Properties.AvailabilityZone = to.Ptr(az)
	}

	// Optional: storage
	if storageMap, ok := props["storage"].(map[string]interface{}); ok {
		storage := &armpostgresqlflexibleservers.Storage{}
		if v, ok := storageMap["storageSizeGB"].(float64); ok {
			storage.StorageSizeGB = to.Ptr(int32(v))
		}
		if v, ok := storageMap["autoGrow"].(string); ok {
			autoGrow := armpostgresqlflexibleservers.StorageAutoGrow(v)
			storage.AutoGrow = &autoGrow
		}
		if v, ok := storageMap["tier"].(string); ok {
			tier := armpostgresqlflexibleservers.AzureManagedDiskPerformanceTiers(v)
			storage.Tier = &tier
		}
		if v, ok := storageMap["iops"].(float64); ok {
			storage.Iops = to.Ptr(int32(v))
		}
		if v, ok := storageMap["throughput"].(float64); ok {
			storage.Throughput = to.Ptr(int32(v))
		}
		params.Properties.Storage = storage
	}

	// Optional: backup
	if backupMap, ok := props["backup"].(map[string]interface{}); ok {
		backup := &armpostgresqlflexibleservers.Backup{}
		if v, ok := backupMap["backupRetentionDays"].(float64); ok {
			backup.BackupRetentionDays = to.Ptr(int32(v))
		}
		if v, ok := backupMap["geoRedundantBackup"].(string); ok {
			geo := armpostgresqlflexibleservers.GeoRedundantBackupEnum(v)
			backup.GeoRedundantBackup = &geo
		}
		params.Properties.Backup = backup
	}

	// Optional: high availability
	if haMap, ok := props["highAvailability"].(map[string]interface{}); ok {
		ha := &armpostgresqlflexibleservers.HighAvailability{}
		if v, ok := haMap["mode"].(string); ok {
			mode := armpostgresqlflexibleservers.HighAvailabilityMode(v)
			ha.Mode = &mode
		}
		if v, ok := haMap["standbyAvailabilityZone"].(string); ok {
			ha.StandbyAvailabilityZone = to.Ptr(v)
		}
		params.Properties.HighAvailability = ha
	}

	// Optional: network
	if networkMap, ok := props["network"].(map[string]interface{}); ok {
		network := &armpostgresqlflexibleservers.Network{}
		if v, ok := networkMap["delegatedSubnetResourceId"].(string); ok {
			network.DelegatedSubnetResourceID = to.Ptr(v)
		}
		if v, ok := networkMap["privateDnsZoneArmResourceId"].(string); ok {
			network.PrivateDNSZoneArmResourceID = to.Ptr(v)
		}
		if v, ok := networkMap["publicNetworkAccess"].(string); ok {
			pna := armpostgresqlflexibleservers.ServerPublicNetworkAccessState(v)
			network.PublicNetworkAccess = &pna
		}
		params.Properties.Network = network
	}

	// Optional: maintenance window
	if mwMap, ok := props["maintenanceWindow"].(map[string]interface{}); ok {
		mw := &armpostgresqlflexibleservers.MaintenanceWindow{}
		if v, ok := mwMap["customWindow"].(string); ok {
			mw.CustomWindow = to.Ptr(v)
		}
		if v, ok := mwMap["dayOfWeek"].(float64); ok {
			mw.DayOfWeek = to.Ptr(int32(v))
		}
		if v, ok := mwMap["startHour"].(float64); ok {
			mw.StartHour = to.Ptr(int32(v))
		}
		if v, ok := mwMap["startMinute"].(float64); ok {
			mw.StartMinute = to.Ptr(int32(v))
		}
		params.Properties.MaintenanceWindow = mw
	}

	// Optional: auth config
	if authMap, ok := props["authConfig"].(map[string]interface{}); ok {
		auth := &armpostgresqlflexibleservers.AuthConfig{}
		if v, ok := authMap["activeDirectoryAuth"].(string); ok {
			ad := armpostgresqlflexibleservers.ActiveDirectoryAuthEnum(v)
			auth.ActiveDirectoryAuth = &ad
		}
		if v, ok := authMap["passwordAuth"].(string); ok {
			pa := armpostgresqlflexibleservers.PasswordAuthEnum(v)
			auth.PasswordAuth = &pa
		}
		if v, ok := authMap["tenantId"].(string); ok {
			auth.TenantID = to.Ptr(v)
		}
		params.Properties.AuthConfig = auth
	}

	// Add tags if present
	if azureTags := formaeTagsToAzureTags(request.Properties); azureTags != nil {
		params.Tags = azureTags
	}

	// Call Azure API to create server (async/LRO operation)
	poller, err := f.Client.FlexibleServersClient.BeginCreate(
		ctx,
		rgName,
		serverName,
		params,
		nil,
	)
	if err != nil {
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start FlexibleServer creation: %w", err)
	}

	// Build expected NativeID
	expectedNativeID := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DBforPostgreSQL/flexibleServers/%s",
		f.Config.SubscriptionId, rgName, serverName)

	// Check if the operation completed synchronously
	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.CreateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationCreate,
					OperationStatus: resource.OperationStatusFailure,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get FlexibleServer create result: %w", err)
		}

		responseProps := f.buildPropertiesFromResult(&result.Server)
		propsJSON, err := json.Marshal(responseProps)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}

		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationCreate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	// Get the ResumeToken for tracking the operation
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	// Encode operation type + resume token as RequestID
	reqID := lroRequestID{
		OperationType: "create",
		ResumeToken:   resumeToken,
		NativeID:      expectedNativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	// Return InProgress - caller should poll Status
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        expectedNativeID,
		},
	}, nil
}

func (f *FlexibleServer) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	// Parse NativeID to extract resourceGroupName and serverName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	serverName, ok := parts["flexibleservers"]
	if !ok || serverName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract server name from %s", request.NativeID)
	}

	// Get server from Azure
	result, err := f.Client.FlexibleServersClient.Get(ctx, rgName, serverName, nil)
	if err != nil {
		return &resource.ReadResult{
			ErrorCode: mapAzureErrorToOperationErrorCode(err),
		}, fmt.Errorf("failed to read FlexibleServer: %w", err)
	}

	responseProps := f.buildPropertiesFromResult(&result.Server)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.ReadResult{
		Properties: string(propsJSON),
	}, nil
}

func (f *FlexibleServer) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	// Parse NativeID to extract resourceGroupName and serverName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	serverName, ok := parts["flexibleservers"]
	if !ok || serverName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract server name from %s", request.NativeID)
	}

	// Parse properties JSON
	var props map[string]interface{}
	if err := json.Unmarshal(request.DesiredProperties, &props); err != nil {
		return nil, fmt.Errorf("failed to parse resource properties: %w", err)
	}

	// Build update parameters
	params := armpostgresqlflexibleservers.ServerForUpdate{}

	// SKU (updatable)
	if skuMap, ok := props["sku"].(map[string]interface{}); ok {
		sku := &armpostgresqlflexibleservers.SKU{}
		if v, ok := skuMap["name"].(string); ok {
			sku.Name = to.Ptr(v)
		}
		if v, ok := skuMap["tier"].(string); ok {
			tier := armpostgresqlflexibleservers.SKUTier(v)
			sku.Tier = &tier
		}
		params.SKU = sku
	}

	// Properties for update
	updateProps := &armpostgresqlflexibleservers.ServerPropertiesForUpdate{}
	hasProps := false

	// Storage (updatable)
	if storageMap, ok := props["storage"].(map[string]interface{}); ok {
		storage := &armpostgresqlflexibleservers.Storage{}
		if v, ok := storageMap["storageSizeGB"].(float64); ok {
			storage.StorageSizeGB = to.Ptr(int32(v))
		}
		if v, ok := storageMap["autoGrow"].(string); ok {
			autoGrow := armpostgresqlflexibleservers.StorageAutoGrow(v)
			storage.AutoGrow = &autoGrow
		}
		if v, ok := storageMap["tier"].(string); ok {
			tier := armpostgresqlflexibleservers.AzureManagedDiskPerformanceTiers(v)
			storage.Tier = &tier
		}
		if v, ok := storageMap["iops"].(float64); ok {
			storage.Iops = to.Ptr(int32(v))
		}
		if v, ok := storageMap["throughput"].(float64); ok {
			storage.Throughput = to.Ptr(int32(v))
		}
		updateProps.Storage = storage
		hasProps = true
	}

	// Backup (updatable)
	if backupMap, ok := props["backup"].(map[string]interface{}); ok {
		backup := &armpostgresqlflexibleservers.Backup{}
		if v, ok := backupMap["backupRetentionDays"].(float64); ok {
			backup.BackupRetentionDays = to.Ptr(int32(v))
		}
		if v, ok := backupMap["geoRedundantBackup"].(string); ok {
			geo := armpostgresqlflexibleservers.GeoRedundantBackupEnum(v)
			backup.GeoRedundantBackup = &geo
		}
		updateProps.Backup = backup
		hasProps = true
	}

	// High availability (updatable)
	if haMap, ok := props["highAvailability"].(map[string]interface{}); ok {
		ha := &armpostgresqlflexibleservers.HighAvailability{}
		if v, ok := haMap["mode"].(string); ok {
			mode := armpostgresqlflexibleservers.HighAvailabilityMode(v)
			ha.Mode = &mode
		}
		if v, ok := haMap["standbyAvailabilityZone"].(string); ok {
			ha.StandbyAvailabilityZone = to.Ptr(v)
		}
		updateProps.HighAvailability = ha
		hasProps = true
	}

	// Maintenance window (updatable)
	if mwMap, ok := props["maintenanceWindow"].(map[string]interface{}); ok {
		mw := &armpostgresqlflexibleservers.MaintenanceWindow{}
		if v, ok := mwMap["customWindow"].(string); ok {
			mw.CustomWindow = to.Ptr(v)
		}
		if v, ok := mwMap["dayOfWeek"].(float64); ok {
			mw.DayOfWeek = to.Ptr(int32(v))
		}
		if v, ok := mwMap["startHour"].(float64); ok {
			mw.StartHour = to.Ptr(int32(v))
		}
		if v, ok := mwMap["startMinute"].(float64); ok {
			mw.StartMinute = to.Ptr(int32(v))
		}
		updateProps.MaintenanceWindow = mw
		hasProps = true
	}

	// Auth config (updatable)
	if authMap, ok := props["authConfig"].(map[string]interface{}); ok {
		auth := &armpostgresqlflexibleservers.AuthConfig{}
		if v, ok := authMap["activeDirectoryAuth"].(string); ok {
			ad := armpostgresqlflexibleservers.ActiveDirectoryAuthEnum(v)
			auth.ActiveDirectoryAuth = &ad
		}
		if v, ok := authMap["passwordAuth"].(string); ok {
			pa := armpostgresqlflexibleservers.PasswordAuthEnum(v)
			auth.PasswordAuth = &pa
		}
		if v, ok := authMap["tenantId"].(string); ok {
			auth.TenantID = to.Ptr(v)
		}
		updateProps.AuthConfig = auth
		hasProps = true
	}

	if hasProps {
		params.Properties = updateProps
	}

	// Add tags if present
	if azureTags := formaeTagsToAzureTags(request.DesiredProperties); azureTags != nil {
		params.Tags = azureTags
	}

	// Call Azure API to update server
	poller, err := f.Client.FlexibleServersClient.BeginUpdate(
		ctx,
		rgName,
		serverName,
		params,
		nil,
	)
	if err != nil {
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start FlexibleServer update: %w", err)
	}

	// Check if the operation completed synchronously
	if poller.Done() {
		result, err := poller.Result(ctx)
		if err != nil {
			return &resource.UpdateResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationUpdate,
					OperationStatus: resource.OperationStatusFailure,
					NativeID:        request.NativeID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				},
			}, fmt.Errorf("failed to get FlexibleServer update result: %w", err)
		}

		responseProps := f.buildPropertiesFromResult(&result.Server)
		propsJSON, err := json.Marshal(responseProps)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal response properties: %w", err)
		}

		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:          resource.OperationUpdate,
				OperationStatus:    resource.OperationStatusSuccess,
				NativeID:           *result.ID,
				ResourceProperties: propsJSON,
			},
		}, nil
	}

	// Get the ResumeToken for tracking the operation
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	// Encode operation type + resume token as RequestID
	reqID := lroRequestID{
		OperationType: "update",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	// Return InProgress - caller should poll Status
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (f *FlexibleServer) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	// Parse NativeID to extract resourceGroupName and serverName
	parts := splitResourceID(request.NativeID)

	rgName, ok := parts["resourcegroups"]
	if !ok || rgName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract resource group name from %s", request.NativeID)
	}

	serverName, ok := parts["flexibleservers"]
	if !ok || serverName == "" {
		return nil, fmt.Errorf("invalid NativeID: could not extract server name from %s", request.NativeID)
	}

	// Start async deletion
	poller, err := f.Client.FlexibleServersClient.BeginDelete(ctx, rgName, serverName, nil)
	if err != nil {
		// If the resource is already gone (NotFound), treat as success
		if mapAzureErrorToOperationErrorCode(err) == resource.OperationErrorCodeNotFound {
			return &resource.DeleteResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					NativeID:        request.NativeID,
				},
			}, nil
		}
		return &resource.DeleteResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
			},
		}, fmt.Errorf("failed to start FlexibleServer deletion: %w", err)
	}

	// Get the ResumeToken for tracking the operation
	resumeToken, err := poller.ResumeToken()
	if err != nil {
		return nil, fmt.Errorf("failed to get resume token: %w", err)
	}

	// Encode operation type + resume token as RequestID
	reqID := lroRequestID{
		OperationType: "delete",
		ResumeToken:   resumeToken,
		NativeID:      request.NativeID,
	}
	reqIDJSON, err := json.Marshal(reqID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request ID: %w", err)
	}

	// Return InProgress - caller should poll Status
	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       string(reqIDJSON),
			NativeID:        request.NativeID,
		},
	}, nil
}

func (f *FlexibleServer) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	// Parse the RequestID to determine operation type
	var reqID lroRequestID
	if err := json.Unmarshal([]byte(request.RequestID), &reqID); err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   fmt.Sprintf("failed to parse request ID: %v", err),
			},
		}, fmt.Errorf("failed to parse request ID: %w", err)
	}

	switch reqID.OperationType {
	case "create":
		return f.statusCreate(ctx, request, &reqID)
	case "update":
		return f.statusUpdate(ctx, request, &reqID)
	case "delete":
		return f.statusDelete(ctx, request, &reqID)
	default:
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   fmt.Sprintf("unknown operation type: %s", reqID.OperationType),
			},
		}, fmt.Errorf("unknown operation type: %s", reqID.OperationType)
	}
}

func (f *FlexibleServer) statusCreate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	// Reconstruct the poller from the resume token
	poller, err := f.Client.ResumeCreateFlexibleServerPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   fmt.Sprintf("failed to resume poller: %v", err),
			},
		}, fmt.Errorf("failed to resume poller from token: %w", err)
	}

	// Check if the operation is already done
	if poller.Done() {
		return f.handleCreateComplete(ctx, request, reqID, poller)
	}

	// Poll for updated status
	_, err = poller.Poll(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	// Check if this poll revealed completion
	if poller.Done() {
		return f.handleCreateComplete(ctx, request, reqID, poller)
	}

	// Still in progress
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationCreate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (f *FlexibleServer) handleCreateComplete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID, poller *runtime.Poller[armpostgresqlflexibleservers.ServersClientCreateResponse]) (*resource.StatusResult, error) {
	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	responseProps := f.buildPropertiesFromResult(&result.Server)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (f *FlexibleServer) statusUpdate(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	// Reconstruct the poller from the resume token
	poller, err := f.Client.ResumeUpdateFlexibleServerPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   fmt.Sprintf("failed to resume poller: %v", err),
			},
		}, fmt.Errorf("failed to resume poller from token: %w", err)
	}

	// Check if the operation is already done
	if poller.Done() {
		return f.handleUpdateComplete(ctx, request, reqID, poller)
	}

	// Poll for updated status
	_, err = poller.Poll(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	// Check if this poll revealed completion
	if poller.Done() {
		return f.handleUpdateComplete(ctx, request, reqID, poller)
	}

	// Still in progress
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationUpdate,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (f *FlexibleServer) handleUpdateComplete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID, poller *runtime.Poller[armpostgresqlflexibleservers.ServersClientUpdateResponse]) (*resource.StatusResult, error) {
	result, err := poller.Result(ctx)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	responseProps := f.buildPropertiesFromResult(&result.Server)
	propsJSON, err := json.Marshal(responseProps)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal response properties: %w", err)
	}

	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           *result.ID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (f *FlexibleServer) statusDelete(ctx context.Context, request *resource.StatusRequest, reqID *lroRequestID) (*resource.StatusResult, error) {
	// Reconstruct the poller from the resume token
	poller, err := f.Client.ResumeDeleteFlexibleServerPoller(reqID.ResumeToken)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
				StatusMessage:   fmt.Sprintf("failed to resume poller: %v", err),
			},
		}, fmt.Errorf("failed to resume poller from token: %w", err)
	}

	// Check if the operation is already done
	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil {
			// NotFound means resource is already deleted - success
			if isDeleteSuccessError(err) {
				return &resource.StatusResult{
					ProgressResult: &resource.ProgressResult{
						Operation:       resource.OperationDelete,
						OperationStatus: resource.OperationStatusSuccess,
						RequestID:       request.RequestID,
						NativeID:        reqID.NativeID,
					},
				}, nil
			}
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
					StatusMessage:   err.Error(),
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	// Poll for updated status
	_, err = poller.Poll(ctx)
	if err != nil {
		// NotFound means resource is already deleted - success
		if isDeleteSuccessError(err) {
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusSuccess,
					RequestID:       request.RequestID,
					NativeID:        reqID.NativeID,
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       mapAzureErrorToOperationErrorCode(err),
				StatusMessage:   err.Error(),
			},
		}, nil
	}

	// Check if this poll revealed completion
	if poller.Done() {
		_, err := poller.Result(ctx)
		if err != nil {
			if isDeleteSuccessError(err) {
				return &resource.StatusResult{
					ProgressResult: &resource.ProgressResult{
						Operation:       resource.OperationDelete,
						OperationStatus: resource.OperationStatusSuccess,
						RequestID:       request.RequestID,
						NativeID:        reqID.NativeID,
					},
				}, nil
			}
			return &resource.StatusResult{
				ProgressResult: &resource.ProgressResult{
					Operation:       resource.OperationDelete,
					OperationStatus: resource.OperationStatusFailure,
					RequestID:       request.RequestID,
					ErrorCode:       mapAzureErrorToOperationErrorCode(err),
					StatusMessage:   err.Error(),
				},
			}, nil
		}
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				RequestID:       request.RequestID,
				NativeID:        reqID.NativeID,
			},
		}, nil
	}

	// Still in progress
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusInProgress,
			RequestID:       request.RequestID,
			NativeID:        reqID.NativeID,
		},
	}, nil
}

func (f *FlexibleServer) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	// Get resourceGroupName from AdditionalProperties
	resourceGroupName, ok := request.AdditionalProperties["resourceGroupName"]
	if !ok || resourceGroupName == "" {
		return nil, fmt.Errorf("resourceGroupName is required in AdditionalProperties for listing FlexibleServers")
	}

	pager := f.Client.FlexibleServersClient.NewListByResourceGroupPager(resourceGroupName, nil)

	var nativeIDs []string

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list flexible servers in resource group %s: %w", resourceGroupName, err)
		}

		for _, server := range page.Value {
			if server.ID == nil {
				continue
			}
			nativeIDs = append(nativeIDs, *server.ID)
		}
	}

	return &resource.ListResult{
		NativeIDs: nativeIDs,
	}, nil
}
