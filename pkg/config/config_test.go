// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFromTargetConfig(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		want := "sub-1"

		got, err := FromTargetConfig(json.RawMessage(`{"SubscriptionId":" sub-1 "}`))

		require.NoError(t, err)
		require.Equal(t, want, got.SubscriptionId)
	})

	t.Run("nil", func(t *testing.T) {
		got, err := FromTargetConfig(nil)

		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("malformed", func(t *testing.T) {
		got, err := FromTargetConfig(json.RawMessage(`{"SubscriptionId":`))

		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("missing subscription", func(t *testing.T) {
		got, err := FromTargetConfig(json.RawMessage(`{}`))

		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("empty subscription", func(t *testing.T) {
		got, err := FromTargetConfig(json.RawMessage(`{"SubscriptionId":"   "}`))

		require.Error(t, err)
		require.Nil(t, got)
	})

	t.Run("wrong subscription type", func(t *testing.T) {
		got, err := FromTargetConfig(json.RawMessage(`{"SubscriptionId":123}`))

		require.Error(t, err)
		require.Nil(t, got)
	})
}
