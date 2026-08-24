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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/trafficmanager/armtrafficmanager"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/client"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/config"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/prov"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/registry"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

const ResourceTypeTrafficManagerProfile = "AZURE::Network::TrafficManagerProfile"

// trafficManagerProfilesAPI is the armtrafficmanager surface used here. Every
// operation is synchronous — Traffic Manager is a DNS control plane, so there is
// nothing to provision and no poller anywhere.
type trafficManagerProfilesAPI interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, profileName string, parameters armtrafficmanager.Profile, options *armtrafficmanager.ProfilesClientCreateOrUpdateOptions) (armtrafficmanager.ProfilesClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, profileName string, options *armtrafficmanager.ProfilesClientGetOptions) (armtrafficmanager.ProfilesClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, profileName string, options *armtrafficmanager.ProfilesClientDeleteOptions) (armtrafficmanager.ProfilesClientDeleteResponse, error)
	NewListBySubscriptionPager(options *armtrafficmanager.ProfilesClientListBySubscriptionOptions) *runtime.Pager[armtrafficmanager.ProfilesClientListBySubscriptionResponse]
	NewListByResourceGroupPager(resourceGroupName string, options *armtrafficmanager.ProfilesClientListByResourceGroupOptions) *runtime.Pager[armtrafficmanager.ProfilesClientListByResourceGroupResponse]
}

func init() {
	registry.Register(ResourceTypeTrafficManagerProfile, func(c *client.Client, cfg *config.Config) prov.Provisioner {
		return &TrafficManagerProfile{api: c.TrafficManagerProfilesClient, config: cfg}
	})
}

// TrafficManagerProfile is the provisioner for Traffic Manager profiles
// (Microsoft.Network/trafficManagerProfiles).
type TrafficManagerProfile struct {
	api    trafficManagerProfilesAPI
	config *config.Config
}

// trafficManagerProfileProps mirrors
// schema/pkl/trafficmanager/trafficmanagerprofile.pkl.
type trafficManagerProfileProps struct {
	Name                 string           `json:"name"`
	ResourceGroupName    string           `json:"resourceGroupName"`
	Location             string           `json:"location"`
	TrafficRoutingMethod string           `json:"trafficRoutingMethod"`
	DNSConfig            *tmDNSConfig     `json:"dnsConfig"`
	MonitorConfig        *tmMonitorConfig `json:"monitorConfig"`
	ProfileStatus        string           `json:"profileStatus"`
	MaxReturn            *int64           `json:"maxReturn"`
}

type tmDNSConfig struct {
	RelativeName string `json:"relativeName"`
	TTL          *int64 `json:"ttl"`
}

type tmMonitorConfig struct {
	Protocol                  string `json:"protocol"`
	Port                      *int64 `json:"port"`
	Path                      string `json:"path"`
	IntervalInSeconds         *int64 `json:"intervalInSeconds"`
	TimeoutInSeconds          *int64 `json:"timeoutInSeconds"`
	ToleratedNumberOfFailures *int64 `json:"toleratedNumberOfFailures"`
}

func trafficManagerProfileIDParts(resourceID string) (rgName, name string, err error) {
	rgName, names, err := armIDParts(resourceID, "trafficmanagerprofiles")
	if err != nil {
		return "", "", err
	}
	return rgName, names["trafficmanagerprofiles"], nil
}

func (t *TrafficManagerProfile) buildPropertiesFromResult(profile *armtrafficmanager.Profile, rgName string) map[string]any {
	props := make(map[string]any)

	props["resourceGroupName"] = rgName

	if profile.ID != nil {
		props["id"] = *profile.ID
	}
	if profile.Name != nil {
		props["name"] = *profile.Name
	}
	// ARM echoes "global" back capitalised as sent; normalise so a read never
	// disagrees with the schema default on case alone.
	if profile.Location != nil {
		loc := *profile.Location
		if strings.EqualFold(loc, "global") {
			loc = "global"
		}
		props["location"] = loc
	}

	if p := profile.Properties; p != nil {
		if p.TrafficRoutingMethod != nil {
			props["trafficRoutingMethod"] = canonicalizeEnum(string(*p.TrafficRoutingMethod),
				"Performance", "Priority", "Weighted", "Geographic", "MultiValue", "Subnet")
		}
		if p.ProfileStatus != nil {
			props["profileStatus"] = canonicalizeEnum(string(*p.ProfileStatus), "Enabled", "Disabled")
		}
		if p.MaxReturn != nil {
			props["maxReturn"] = *p.MaxReturn
		}
		if d := p.DNSConfig; d != nil {
			entry := map[string]any{}
			if d.RelativeName != nil {
				entry["relativeName"] = *d.RelativeName
			}
			if d.TTL != nil {
				entry["ttl"] = *d.TTL
			}
			if len(entry) > 0 {
				props["dnsConfig"] = entry
			}
			if d.Fqdn != nil {
				props["fqdn"] = *d.Fqdn
			}
		}
		if m := p.MonitorConfig; m != nil {
			entry := map[string]any{}
			if m.Protocol != nil {
				entry["protocol"] = canonicalizeEnum(string(*m.Protocol), "HTTP", "HTTPS", "TCP")
			}
			if m.Port != nil {
				entry["port"] = *m.Port
			}
			if m.Path != nil {
				entry["path"] = *m.Path
			}
			if m.IntervalInSeconds != nil {
				entry["intervalInSeconds"] = *m.IntervalInSeconds
			}
			if m.TimeoutInSeconds != nil {
				entry["timeoutInSeconds"] = *m.TimeoutInSeconds
			}
			if m.ToleratedNumberOfFailures != nil {
				entry["toleratedNumberOfFailures"] = *m.ToleratedNumberOfFailures
			}
			if len(entry) > 0 {
				props["monitorConfig"] = entry
			}
		}
	}

	if tags := azureTagsToFormaeTags(profile.Tags); tags != nil {
		props["Tags"] = tags
	}

	return props
}

func trafficManagerProfileParams(props trafficManagerProfileProps) armtrafficmanager.Profile {
	location := props.Location
	if location == "" {
		location = "global"
	}

	profileProps := &armtrafficmanager.ProfileProperties{}
	if props.TrafficRoutingMethod != "" {
		profileProps.TrafficRoutingMethod = to.Ptr(armtrafficmanager.TrafficRoutingMethod(props.TrafficRoutingMethod))
	}
	if props.ProfileStatus != "" {
		profileProps.ProfileStatus = to.Ptr(armtrafficmanager.ProfileStatus(props.ProfileStatus))
	}
	if props.MaxReturn != nil {
		profileProps.MaxReturn = props.MaxReturn
	}
	if d := props.DNSConfig; d != nil {
		dns := &armtrafficmanager.DNSConfig{}
		if d.RelativeName != "" {
			dns.RelativeName = to.Ptr(d.RelativeName)
		}
		if d.TTL != nil {
			dns.TTL = d.TTL
		}
		profileProps.DNSConfig = dns
	}
	if m := props.MonitorConfig; m != nil {
		mon := &armtrafficmanager.MonitorConfig{}
		if m.Protocol != "" {
			mon.Protocol = to.Ptr(armtrafficmanager.MonitorProtocol(m.Protocol))
		}
		if m.Port != nil {
			mon.Port = m.Port
		}
		// path is meaningless for a TCP probe and ARM rejects it there.
		if m.Path != "" && !strings.EqualFold(m.Protocol, "TCP") {
			mon.Path = to.Ptr(m.Path)
		}
		if m.IntervalInSeconds != nil {
			mon.IntervalInSeconds = m.IntervalInSeconds
		}
		if m.TimeoutInSeconds != nil {
			mon.TimeoutInSeconds = m.TimeoutInSeconds
		}
		if m.ToleratedNumberOfFailures != nil {
			mon.ToleratedNumberOfFailures = m.ToleratedNumberOfFailures
		}
		profileProps.MonitorConfig = mon
	}

	return armtrafficmanager.Profile{
		Location:   to.Ptr(location),
		Properties: profileProps,
	}
}

// upsert backs both Create and Update: CreateOrUpdate replaces the profile body,
// and ARM's Update is a partial merge of the same type.
func (t *TrafficManagerProfile) upsert(ctx context.Context, payload json.RawMessage, label string) (armtrafficmanager.Profile, string, string, error) {
	var props trafficManagerProfileProps
	if err := json.Unmarshal(payload, &props); err != nil {
		return armtrafficmanager.Profile{}, "", "", fmt.Errorf("failed to parse resource properties: %w", err)
	}
	if props.ResourceGroupName == "" {
		return armtrafficmanager.Profile{}, "", "", fmt.Errorf("resourceGroupName is required")
	}
	if props.DNSConfig == nil || props.DNSConfig.RelativeName == "" {
		return armtrafficmanager.Profile{}, "", "", fmt.Errorf("dnsConfig.relativeName is required")
	}
	if props.TrafficRoutingMethod == "" {
		return armtrafficmanager.Profile{}, "", "", fmt.Errorf("trafficRoutingMethod is required")
	}
	name := props.Name
	if name == "" {
		name = label
	}
	if name == "" {
		return armtrafficmanager.Profile{}, "", "", fmt.Errorf("name is required")
	}

	params := trafficManagerProfileParams(props)
	if azureTags := formaeTagsToAzureTags(payload); azureTags != nil {
		params.Tags = azureTags
	}

	result, err := t.api.CreateOrUpdate(ctx, props.ResourceGroupName, name, params, nil)
	if err != nil {
		return armtrafficmanager.Profile{}, props.ResourceGroupName, name, err
	}
	return result.Profile, props.ResourceGroupName, name, nil
}

func (t *TrafficManagerProfile) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	profile, rgName, name, err := t.upsert(ctx, request.Properties, request.Label)
	if err != nil {
		if rgName == "" || name == "" {
			return nil, err
		}
		return &resource.CreateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationCreate,
				OperationStatus: resource.OperationStatusFailure,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&profile, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize TrafficManagerProfile properties: %w", err)
	}

	nativeID := ""
	if profile.ID != nil {
		nativeID = *profile.ID
	}
	return &resource.CreateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationCreate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (t *TrafficManagerProfile) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	rgName, name, err := trafficManagerProfileIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	result, err := t.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.ReadResult{ErrorCode: operationErrorCode(err)}, nil
	}

	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.Profile, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize TrafficManagerProfile properties: %w", err)
	}
	return &resource.ReadResult{
		ResourceType: ResourceTypeTrafficManagerProfile,
		Properties:   string(propsJSON),
	}, nil
}

func (t *TrafficManagerProfile) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	profile, rgName, name, err := t.upsert(ctx, request.DesiredProperties, "")
	if err != nil {
		if rgName == "" || name == "" {
			return nil, err
		}
		return &resource.UpdateResult{
			ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationUpdate,
				OperationStatus: resource.OperationStatusFailure,
				NativeID:        request.NativeID,
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&profile, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize TrafficManagerProfile properties after update: %w", err)
	}
	return &resource.UpdateResult{
		ProgressResult: &resource.ProgressResult{
			Operation:          resource.OperationUpdate,
			OperationStatus:    resource.OperationStatusSuccess,
			NativeID:           request.NativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (t *TrafficManagerProfile) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	rgName, name, err := trafficManagerProfileIDParts(request.NativeID)
	if err != nil {
		return nil, err
	}

	if _, err := t.api.Delete(ctx, rgName, name, nil); err != nil {
		if operationErrorCode(err) == resource.OperationErrorCodeNotFound {
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
				ErrorCode:       operationErrorCode(err),
			},
		}, nil
	}

	return &resource.DeleteResult{
		ProgressResult: &resource.ProgressResult{
			Operation:       resource.OperationDelete,
			OperationStatus: resource.OperationStatusSuccess,
			NativeID:        request.NativeID,
		},
	}, nil
}

// All Traffic Manager operations are synchronous, so Status just re-reads.
func (t *TrafficManagerProfile) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	rgName, name, err := trafficManagerProfileIDParts(request.NativeID)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       resource.OperationErrorCodeGeneralServiceException,
			},
		}, err
	}

	result, err := t.api.Get(ctx, rgName, name, nil)
	if err != nil {
		return &resource.StatusResult{
			ProgressResult: &resource.ProgressResult{
				OperationStatus: resource.OperationStatusFailure,
				RequestID:       request.RequestID,
				ErrorCode:       operationErrorCode(err),
			},
		}, fmt.Errorf("failed to get TrafficManagerProfile status: %w", err)
	}

	propsJSON, err := json.Marshal(t.buildPropertiesFromResult(&result.Profile, rgName))
	if err != nil {
		return nil, fmt.Errorf("failed to serialize TrafficManagerProfile properties: %w", err)
	}
	nativeID := request.NativeID
	if result.ID != nil {
		nativeID = *result.ID
	}
	return &resource.StatusResult{
		ProgressResult: &resource.ProgressResult{
			OperationStatus:    resource.OperationStatusSuccess,
			RequestID:          request.RequestID,
			NativeID:           nativeID,
			ResourceProperties: propsJSON,
		},
	}, nil
}

func (t *TrafficManagerProfile) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	rgName := request.AdditionalProperties["resourceGroupName"]

	var nativeIDs []string

	if rgName != "" {
		pager := t.api.NewListByResourceGroupPager(rgName, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to list traffic manager profiles: %w", err)
			}
			for _, profile := range page.Value {
				if profile.ID != nil {
					nativeIDs = append(nativeIDs, *profile.ID)
				}
			}
		}
		return &resource.ListResult{NativeIDs: nativeIDs}, nil
	}

	pager := t.api.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list traffic manager profiles: %w", err)
		}
		for _, profile := range page.Value {
			if profile.ID != nil {
				nativeIDs = append(nativeIDs, *profile.ID)
			}
		}
	}
	return &resource.ListResult{NativeIDs: nativeIDs}, nil
}
