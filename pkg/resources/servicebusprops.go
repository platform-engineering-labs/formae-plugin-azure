// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import "github.com/Azure/azure-sdk-for-go/sdk/azcore/to"

// Small readers shared by the Service Bus queue/topic/subscription provisioners.
// Each returns nil when the property is absent so an omitted field is left out of
// the ARM body entirely rather than sent as a zero value — Service Bus treats an
// explicit 0/"" very differently from "not specified".

func sbOptString(props map[string]any, key string) *string {
	if v, ok := props[key].(string); ok && v != "" {
		return to.Ptr(v)
	}
	return nil
}

func sbOptBool(props map[string]any, key string) *bool {
	if v, ok := props[key].(bool); ok {
		return to.Ptr(v)
	}
	return nil
}

func sbOptInt32(props map[string]any, key string) *int32 {
	if v, ok := props[key].(float64); ok {
		return to.Ptr(int32(v))
	}
	return nil
}

func sbOptInt64(props map[string]any, key string) *int64 {
	if v, ok := props[key].(float64); ok {
		return to.Ptr(int64(v))
	}
	return nil
}

// Writers used when serializing an ARM response back into Formae properties. They
// skip nil so a property Azure did not return stays absent instead of appearing as
// a zero value that would read as drift.

func sbPutString(props map[string]any, key string, v *string) {
	if v != nil {
		props[key] = *v
	}
}

func sbPutBool(props map[string]any, key string, v *bool) {
	if v != nil {
		props[key] = *v
	}
}

func sbPutInt32(props map[string]any, key string, v *int32) {
	if v != nil {
		props[key] = int(*v)
	}
}

func sbPutInt64(props map[string]any, key string, v *int64) {
	if v != nil {
		props[key] = int(*v)
	}
}
