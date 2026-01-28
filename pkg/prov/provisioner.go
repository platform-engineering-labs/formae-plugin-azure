// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package prov

import (
	"context"

	"github.com/platform-engineering-labs/formae/pkg/plugin/resource"
)

// Provisioner is the interface that all Azure resource provisioners must implement.
type Provisioner interface {
	Create(ctx context.Context, request *resource.CreateRequest) (*resource.CreateResult, error)
	Update(ctx context.Context, request *resource.UpdateRequest) (*resource.UpdateResult, error)
	Delete(ctx context.Context, request *resource.DeleteRequest) (*resource.DeleteResult, error)
	Read(ctx context.Context, request *resource.ReadRequest) (*resource.ReadResult, error)
	Status(ctx context.Context, request *resource.StatusRequest) (*resource.StatusResult, error)
	List(ctx context.Context, request *resource.ListRequest) (*resource.ListResult, error)
}
