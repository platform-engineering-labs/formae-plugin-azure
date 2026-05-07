// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package prov

import (
	"context"
	"fmt"

	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/nativeid"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

// Wrap adds provider-wide operation handling around a resource provisioner.
func Wrap(p Provisioner) Provisioner {
	return &azureProvisioner{inner: p}
}

type azureProvisioner struct {
	inner Provisioner
}

var _ Provisioner = &azureProvisioner{}

func (p *azureProvisioner) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	result, err := p.inner.Create(ctx, request)
	if err != nil {
		return createFailure(err)
	}
	if result == nil || result.ProgressResult == nil {
		return nil, fmt.Errorf("create returned nil progress result")
	}
	return result, nil
}

func (p *azureProvisioner) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	request.NativeID = nativeid.NativeID(request.NativeID).ArmID()
	result, err := p.inner.Read(ctx, request)
	if err != nil {
		if code, ok := AzureErrorCode(err); ok {
			return &resource.ReadResult{ResourceType: request.ResourceType, ErrorCode: code}, nil
		}
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("read returned nil result")
	}
	return result, nil
}

func (p *azureProvisioner) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	request.NativeID = nativeid.NativeID(request.NativeID).ArmID()
	result, err := p.inner.Update(ctx, request)
	if err != nil {
		return updateFailure(request.NativeID, err)
	}
	if result == nil || result.ProgressResult == nil {
		return nil, fmt.Errorf("update returned nil progress result")
	}
	return result, nil
}

func (p *azureProvisioner) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	request.NativeID = nativeid.NativeID(request.NativeID).ArmID()
	result, err := p.inner.Delete(ctx, request)
	if err != nil {
		if IsDeleteSuccessError(err) {
			return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
				Operation:       resource.OperationDelete,
				OperationStatus: resource.OperationStatusSuccess,
				NativeID:        request.NativeID,
			}}, nil
		}
		return deleteFailure(request.NativeID, err)
	}
	if result == nil || result.ProgressResult == nil {
		return nil, fmt.Errorf("delete returned nil progress result")
	}
	return result, nil
}

func (p *azureProvisioner) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	request.NativeID = nativeid.NativeID(request.NativeID).ArmID()
	result, err := p.inner.Status(ctx, request)
	if err != nil {
		return statusFailure(request.RequestID, err)
	}
	if result == nil || result.ProgressResult == nil {
		return nil, fmt.Errorf("status returned nil progress result")
	}
	return result, nil
}

func (p *azureProvisioner) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	return p.inner.List(ctx, request)
}

func createFailure(err error) (*resource.CreateResult, error) {
	code, ok := AzureErrorCode(err)
	if !ok {
		return nil, err
	}
	return &resource.CreateResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationCreate,
		OperationStatus: resource.OperationStatusFailure,
		ErrorCode:       code,
	}}, nil
}

func updateFailure(nativeID string, err error) (*resource.UpdateResult, error) {
	code, ok := AzureErrorCode(err)
	if !ok {
		return nil, err
	}
	return &resource.UpdateResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationUpdate,
		OperationStatus: resource.OperationStatusFailure,
		NativeID:        nativeID,
		ErrorCode:       code,
	}}, nil
}

func deleteFailure(nativeID string, err error) (*resource.DeleteResult, error) {
	code, ok := AzureErrorCode(err)
	if !ok {
		return nil, err
	}
	return &resource.DeleteResult{ProgressResult: &resource.ProgressResult{
		Operation:       resource.OperationDelete,
		OperationStatus: resource.OperationStatusFailure,
		NativeID:        nativeID,
		ErrorCode:       code,
	}}, nil
}

func statusFailure(requestID string, err error) (*resource.StatusResult, error) {
	code, ok := AzureErrorCode(err)
	if !ok {
		return nil, err
	}
	return &resource.StatusResult{ProgressResult: &resource.ProgressResult{
		OperationStatus: resource.OperationStatusFailure,
		RequestID:       requestID,
		ErrorCode:       code,
	}}, nil
}
