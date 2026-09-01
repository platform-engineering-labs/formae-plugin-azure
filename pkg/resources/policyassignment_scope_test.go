// © 2026 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build unit

package resources

import "testing"

// ARM's subscription-scoped list returns every assignment that APPLIES to the
// subscription, which includes ones assigned on a management group above it.
// Importing those makes an inventory formae cannot maintain: the identity is
// granted at subscription scope, so the follow-up read is refused, and the
// resource fails on every sync from then on. One inherited assignment was
// enough to fire a high-severity alert every sync cycle.
//
// Anything at or below the subscription is ours to manage; anything above it is
// not.
func TestPolicyAssignmentIsWithinSubscription(t *testing.T) {
	const sub = "b161e970-a04d-48a4-ac91-18d06e8d8047"

	for _, tc := range []struct {
		name string
		id   string
		want bool
	}{
		{
			name: "assigned on the subscription",
			id:   "/subscriptions/" + sub + "/providers/Microsoft.Authorization/policyAssignments/mine",
			want: true,
		},
		{
			name: "assigned on a resource group in the subscription",
			id:   "/subscriptions/" + sub + "/resourceGroups/rg1/providers/Microsoft.Authorization/policyAssignments/mine",
			want: true,
		},
		{
			// The case that caused this: a Microsoft-managed region restriction
			// assigned on the tenant's root management group.
			name: "inherited from a management group",
			id:   "/providers/Microsoft.Management/managementGroups/416727bd-1d5d-4540-81d7-d391007ed660/providers/Microsoft.Authorization/policyAssignments/sys.blockwesteurope",
			want: false,
		},
		{
			name: "assigned on a different subscription",
			id:   "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/policyAssignments/theirs",
			want: false,
		},
		{
			// ARM is inconsistent about casing in resource ids, and a casing
			// difference must not silently drop an assignment that is ours.
			name: "our subscription, upper-case segment",
			id:   "/SUBSCRIPTIONS/" + sub + "/providers/Microsoft.Authorization/policyAssignments/mine",
			want: true,
		},
		{
			name: "empty id",
			id:   "",
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := policyAssignmentIsWithinSubscription(tc.id, sub); got != tc.want {
				t.Errorf("got %v, want %v for %q", got, tc.want, tc.id)
			}
		})
	}
}

// The resource-group pager needs the same filter as the subscription-wide one.
// The SDK says its unfiltered list "includes all policy assignments associated
// with the resource group, including those that apply directly or apply from
// containing scopes" — and a management group is a containing scope, so an
// inherited assignment arrives through that path too. This was originally
// dismissed as impossible; it is not.
func TestPolicyAssignmentScopeFilterAppliesToResourceGroupListings(t *testing.T) {
	const sub = "b161e970-a04d-48a4-ac91-18d06e8d8047"

	// What an unfiltered resource-group list can return, per the SDK: the
	// assignment made on the group, one inherited from the subscription, one
	// inherited from a management group, and one on a resource inside the group.
	inGroup := "/subscriptions/" + sub + "/resourceGroups/rg1/providers/Microsoft.Authorization/policyAssignments/ongroup"
	fromSubscription := "/subscriptions/" + sub + "/providers/Microsoft.Authorization/policyAssignments/onsub"
	fromManagementGroup := "/providers/Microsoft.Management/managementGroups/mg1/providers/Microsoft.Authorization/policyAssignments/sys.blockwesteurope"
	onNestedResource := "/subscriptions/" + sub + "/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/sa1/providers/Microsoft.Authorization/policyAssignments/onresource"

	for _, id := range []string{inGroup, fromSubscription, onNestedResource} {
		if !policyAssignmentIsWithinSubscription(id, sub) {
			t.Errorf("readable assignment was excluded: %s", id)
		}
	}
	if policyAssignmentIsWithinSubscription(fromManagementGroup, sub) {
		t.Errorf("management-group assignment was kept: %s", fromManagementGroup)
	}
}
