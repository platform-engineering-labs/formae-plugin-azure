// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package prov

import (
	"context"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/platform-engineering-labs/formae-plugin-azure/pkg/nativeid"
	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestWrapNormalizesNativeIDs(t *testing.T) {
	ctx := context.Background()
	rawID := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/privateEndpoints/pe-1"
	encodedID := nativeid.Encode(rawID).String()

	t.Run("read", func(t *testing.T) {
		inner := &mockProvisioner{}
		inner.On("Read", mock.Anything, mock.MatchedBy(func(req *resource.ReadRequest) bool {
			return req.NativeID == rawID
		})).Return(&resource.ReadResult{ResourceType: "AZURE::Test"}, nil).Once()
		wrapped := Wrap(inner)

		got, err := wrapped.Read(ctx, &resource.ReadRequest{NativeID: encodedID, ResourceType: "AZURE::Test"})

		require.NoError(t, err)
		require.Equal(t, "AZURE::Test", got.ResourceType)
		inner.AssertExpectations(t)
	})

	t.Run("update", func(t *testing.T) {
		inner := &mockProvisioner{}
		inner.On("Update", mock.Anything, mock.MatchedBy(func(req *resource.UpdateRequest) bool {
			return req.NativeID == rawID
		})).Return(&resource.UpdateResult{ProgressResult: &resource.ProgressResult{OperationStatus: resource.OperationStatusSuccess}}, nil).Once()
		wrapped := Wrap(inner)

		got, err := wrapped.Update(ctx, &resource.UpdateRequest{NativeID: encodedID, ResourceType: "AZURE::Test"})

		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		inner.AssertExpectations(t)
	})

	t.Run("delete", func(t *testing.T) {
		inner := &mockProvisioner{}
		inner.On("Delete", mock.Anything, mock.MatchedBy(func(req *resource.DeleteRequest) bool {
			return req.NativeID == rawID
		})).Return(&resource.DeleteResult{ProgressResult: &resource.ProgressResult{OperationStatus: resource.OperationStatusSuccess}}, nil).Once()
		wrapped := Wrap(inner)

		got, err := wrapped.Delete(ctx, &resource.DeleteRequest{NativeID: encodedID, ResourceType: "AZURE::Test"})

		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		inner.AssertExpectations(t)
	})

	t.Run("status", func(t *testing.T) {
		inner := &mockProvisioner{}
		inner.On("Status", mock.Anything, mock.MatchedBy(func(req *resource.StatusRequest) bool {
			return req.NativeID == rawID
		})).Return(&resource.StatusResult{ProgressResult: &resource.ProgressResult{OperationStatus: resource.OperationStatusSuccess}}, nil).Once()
		wrapped := Wrap(inner)

		got, err := wrapped.Status(ctx, &resource.StatusRequest{NativeID: encodedID, ResourceType: "AZURE::Test"})

		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		inner.AssertExpectations(t)
	})
}

func TestWrapMapsAzureErrors(t *testing.T) {
	ctx := context.Background()
	rawID := "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Network/privateEndpoints/pe-1"

	t.Run("create", func(t *testing.T) {
		inner := &mockProvisioner{}
		inner.On("Create", mock.Anything, mock.AnythingOfType("*resource.CreateRequest")).
			Return((*resource.CreateResult)(nil), &azcore.ResponseError{StatusCode: 403}).Once()
		wrapped := Wrap(inner)

		got, err := wrapped.Create(ctx, &resource.CreateRequest{ResourceType: "AZURE::Test"})

		require.NoError(t, err)
		require.Equal(t, resource.OperationCreate, got.ProgressResult.Operation)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, resource.OperationErrorCodeAccessDenied, got.ProgressResult.ErrorCode)
		inner.AssertExpectations(t)
	})

	t.Run("read", func(t *testing.T) {
		inner := &mockProvisioner{}
		inner.On("Read", mock.Anything, mock.AnythingOfType("*resource.ReadRequest")).
			Return((*resource.ReadResult)(nil), &azcore.ResponseError{StatusCode: 404}).Once()
		wrapped := Wrap(inner)

		got, err := wrapped.Read(ctx, &resource.ReadRequest{NativeID: rawID, ResourceType: "AZURE::Test"})

		require.NoError(t, err)
		require.Equal(t, "AZURE::Test", got.ResourceType)
		require.Equal(t, resource.OperationErrorCodeNotFound, got.ErrorCode)
		inner.AssertExpectations(t)
	})

	t.Run("update", func(t *testing.T) {
		inner := &mockProvisioner{}
		inner.On("Update", mock.Anything, mock.AnythingOfType("*resource.UpdateRequest")).
			Return((*resource.UpdateResult)(nil), &azcore.ResponseError{StatusCode: 409}).Once()
		wrapped := Wrap(inner)

		got, err := wrapped.Update(ctx, &resource.UpdateRequest{NativeID: rawID, ResourceType: "AZURE::Test"})

		require.NoError(t, err)
		require.Equal(t, resource.OperationUpdate, got.ProgressResult.Operation)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, rawID, got.ProgressResult.NativeID)
		require.Equal(t, resource.OperationErrorCodeResourceConflict, got.ProgressResult.ErrorCode)
		inner.AssertExpectations(t)
	})

	t.Run("delete not found succeeds", func(t *testing.T) {
		inner := &mockProvisioner{}
		inner.On("Delete", mock.Anything, mock.AnythingOfType("*resource.DeleteRequest")).
			Return((*resource.DeleteResult)(nil), &azcore.ResponseError{StatusCode: 404}).Once()
		wrapped := Wrap(inner)

		got, err := wrapped.Delete(ctx, &resource.DeleteRequest{NativeID: rawID, ResourceType: "AZURE::Test"})

		require.NoError(t, err)
		require.Equal(t, resource.OperationDelete, got.ProgressResult.Operation)
		require.Equal(t, resource.OperationStatusSuccess, got.ProgressResult.OperationStatus)
		require.Equal(t, rawID, got.ProgressResult.NativeID)
		inner.AssertExpectations(t)
	})

	t.Run("status", func(t *testing.T) {
		inner := &mockProvisioner{}
		inner.On("Status", mock.Anything, mock.AnythingOfType("*resource.StatusRequest")).
			Return((*resource.StatusResult)(nil), &azcore.ResponseError{StatusCode: 429}).Once()
		wrapped := Wrap(inner)

		got, err := wrapped.Status(ctx, &resource.StatusRequest{RequestID: "req-1", NativeID: rawID, ResourceType: "AZURE::Test"})

		require.NoError(t, err)
		require.Equal(t, resource.OperationStatusFailure, got.ProgressResult.OperationStatus)
		require.Equal(t, "req-1", got.ProgressResult.RequestID)
		require.Equal(t, resource.OperationErrorCodeThrottling, got.ProgressResult.ErrorCode)
		inner.AssertExpectations(t)
	})
}

func TestWrapPassesThroughUnknownErrors(t *testing.T) {
	ctx := context.Background()
	want := errors.New("invalid local resource shape")
	inner := &mockProvisioner{}
	inner.On("Create", mock.Anything, mock.AnythingOfType("*resource.CreateRequest")).
		Return((*resource.CreateResult)(nil), want).Once()
	wrapped := Wrap(inner)

	got, err := wrapped.Create(ctx, &resource.CreateRequest{ResourceType: "AZURE::Test"})

	require.ErrorIs(t, err, want)
	require.Nil(t, got)
	inner.AssertExpectations(t)
}

func TestWrapRejectsNilResults(t *testing.T) {
	ctx := context.Background()
	inner := &mockProvisioner{}
	inner.On("Create", mock.Anything, mock.AnythingOfType("*resource.CreateRequest")).
		Return((*resource.CreateResult)(nil), nil).Once()
	wrapped := Wrap(inner)

	got, err := wrapped.Create(ctx, &resource.CreateRequest{ResourceType: "AZURE::Test"})

	require.Error(t, err)
	require.Nil(t, got)
	inner.AssertExpectations(t)
}

type mockProvisioner struct {
	mock.Mock
}

func (m *mockProvisioner) Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*resource.CreateResult), args.Error(1)
}

func (m *mockProvisioner) Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*resource.ReadResult), args.Error(1)
}

func (m *mockProvisioner) Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*resource.UpdateResult), args.Error(1)
}

func (m *mockProvisioner) Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*resource.DeleteResult), args.Error(1)
}

func (m *mockProvisioner) Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*resource.StatusResult), args.Error(1)
}

func (m *mockProvisioner) List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error) {
	args := m.Called(ctx, request)
	return args.Get(0).(*resource.ListResult), args.Error(1)
}
