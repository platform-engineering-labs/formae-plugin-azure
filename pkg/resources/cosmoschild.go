// © 2025 Platform Engineering Labs Inc.
//
// SPDX-License-Identifier: FSL-1.1-ALv2

package resources

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v3"
)

// This file holds the pieces every Cosmos DB data-model child resource shares:
// the ARM ID prefix, the throughput block, and the container-shaped policy
// converters that SQL containers and Gremlin graphs both use.
//
// Each API family (SQL, MongoDB, Cassandra, Gremlin, Table) gets its own
// provisioner file; only genuinely identical shapes live here.

// cosmosProviderNamespace is the ARM provider every Cosmos child hangs off.
const cosmosProviderNamespace = "Microsoft.DocumentDB"

// cosmosChildNativeID builds the ARM ID of a Cosmos child resource so an
// in-flight LRO can pin its native ID before the operation completes.
//
// segments alternate type and name, e.g. ("sqlDatabases", "db", "containers",
// "items").
func cosmosChildNativeID(subscriptionID, rgName, accountName string, segments ...string) string {
	id := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/%s/databaseAccounts/%s",
		subscriptionID, rgName, cosmosProviderNamespace, accountName)
	for _, segment := range segments {
		id += "/" + segment
	}
	return id
}

// cosmosChildThroughput is the throughput block shared by every Cosmos data-model
// child that can carry provisioned RU/s.
//
// ARM takes exactly one of the two: `throughput` for manual RU/s or
// `autoscaleSettings.maxThroughput` for autoscale. Both fields are createOnly in
// the schema, for two reasons:
//
//   - Switching between manual and autoscale is not a property change at all. It
//     needs the dedicated MigrateXToAutoscale / MigrateXToManualThroughput ARM
//     operations, which this plugin does not model.
//   - Changing the value within one mode needs UpdateXThroughput, a separate
//     sub-resource (`.../throughputSettings/default`), not the CreateUpdate body.
//     `options` on a CreateUpdate maps to request *headers* that ARM honours only
//     at create time, so echoing a new value there would silently do nothing.
//
// Leaving both unset is the correct shape for a serverless account and for a
// container inside a shared-throughput database — ARM rejects throughput outright
// on serverless.
type cosmosChildThroughput struct {
	Throughput             *int32 `json:"throughput"`
	AutoscaleMaxThroughput *int32 `json:"autoscaleMaxThroughput"`
}

// cosmosCreateUpdateOptions renders the throughput block into the ARM
// create-options bag. Returns nil when neither is set, so the request omits the
// headers entirely rather than asking for 0 RU/s.
func cosmosCreateUpdateOptions(t cosmosChildThroughput) (*armcosmos.CreateUpdateOptions, error) {
	if t.Throughput != nil && t.AutoscaleMaxThroughput != nil {
		return nil, fmt.Errorf("throughput and autoscaleMaxThroughput are mutually exclusive")
	}
	switch {
	case t.AutoscaleMaxThroughput != nil:
		return &armcosmos.CreateUpdateOptions{
			AutoscaleSettings: &armcosmos.AutoscaleSettings{MaxThroughput: t.AutoscaleMaxThroughput},
		}, nil
	case t.Throughput != nil:
		return &armcosmos.CreateUpdateOptions{Throughput: t.Throughput}, nil
	default:
		return nil, nil
	}
}

// cosmosPutThroughput records provisioned throughput read back from a
// GetXThroughput call onto the property map.
//
// Only one of the two keys is ever emitted. An autoscale resource reports BOTH
// `autoscaleSettings.maxThroughput` (the ceiling the caller asked for) and
// `throughput` (whatever RU/s it happens to be scaled to right now); echoing the
// latter would invent a manual-throughput field that desired state never
// declared, and it changes on its own, so it would report drift forever.
func cosmosPutThroughput(props map[string]any, res *armcosmos.ThroughputSettingsGetPropertiesResource) {
	if res == nil {
		return
	}
	if res.AutoscaleSettings != nil && res.AutoscaleSettings.MaxThroughput != nil {
		props["autoscaleMaxThroughput"] = *res.AutoscaleSettings.MaxThroughput
		return
	}
	if res.Throughput != nil {
		props["throughput"] = *res.Throughput
	}
}

// --- container-shaped policies (SQL container and Gremlin graph) ---

type cosmosPartitionKeyProps struct {
	Paths   []string `json:"paths"`
	Kind    string   `json:"kind"`
	Version *int32   `json:"version"`
}

type cosmosIndexesProps struct {
	DataType  string `json:"dataType"`
	Kind      string `json:"kind"`
	Precision *int32 `json:"precision"`
}

type cosmosIncludedPathProps struct {
	Path    string               `json:"path"`
	Indexes []cosmosIndexesProps `json:"indexes"`
}

type cosmosExcludedPathProps struct {
	Path string `json:"path"`
}

type cosmosCompositePathProps struct {
	Path  string `json:"path"`
	Order string `json:"order"`
}

type cosmosSpatialSpecProps struct {
	Path  string   `json:"path"`
	Types []string `json:"types"`
}

type cosmosIndexingPolicyProps struct {
	Automatic        *bool                        `json:"automatic"`
	IndexingMode     string                       `json:"indexingMode"`
	IncludedPaths    []cosmosIncludedPathProps    `json:"includedPaths"`
	ExcludedPaths    []cosmosExcludedPathProps    `json:"excludedPaths"`
	CompositeIndexes [][]cosmosCompositePathProps `json:"compositeIndexes"`
	SpatialIndexes   []cosmosSpatialSpecProps     `json:"spatialIndexes"`
}

type cosmosConflictResolutionPolicyProps struct {
	Mode                        string `json:"mode"`
	ConflictResolutionPath      string `json:"conflictResolutionPath"`
	ConflictResolutionProcedure string `json:"conflictResolutionProcedure"`
}

type cosmosUniqueKeyProps struct {
	Paths []string `json:"paths"`
}

type cosmosUniqueKeyPolicyProps struct {
	UniqueKeys []cosmosUniqueKeyProps `json:"uniqueKeys"`
}

func cosmosPartitionKeyToARM(p *cosmosPartitionKeyProps) *armcosmos.ContainerPartitionKey {
	if p == nil {
		return nil
	}
	pk := &armcosmos.ContainerPartitionKey{
		Paths:   stringPointers(p.Paths),
		Version: p.Version,
	}
	if p.Kind != "" {
		pk.Kind = to.Ptr(armcosmos.PartitionKind(p.Kind))
	}
	return pk
}

// cosmosPartitionKeyFromARM omits SystemKey: it is service-assigned and nested,
// and hasProviderDefault only applies to top-level fields, so surfacing it would
// read as permanent drift.
func cosmosPartitionKeyFromARM(pk *armcosmos.ContainerPartitionKey) map[string]any {
	if pk == nil {
		return nil
	}
	entry := map[string]any{}
	if paths := stringsFromPointers(pk.Paths); len(paths) > 0 {
		entry["paths"] = paths
	}
	if pk.Kind != nil {
		entry["kind"] = canonicalizeEnum(string(*pk.Kind), "Hash", "MultiHash", "Range")
	}
	if pk.Version != nil {
		entry["version"] = *pk.Version
	}
	if len(entry) == 0 {
		return nil
	}
	return entry
}

func cosmosIndexingPolicyToARM(p *cosmosIndexingPolicyProps) *armcosmos.IndexingPolicy {
	if p == nil {
		return nil
	}
	policy := &armcosmos.IndexingPolicy{Automatic: p.Automatic}
	if p.IndexingMode != "" {
		policy.IndexingMode = to.Ptr(armcosmos.IndexingMode(p.IndexingMode))
	}
	for _, included := range p.IncludedPaths {
		entry := &armcosmos.IncludedPath{Path: to.Ptr(included.Path)}
		for _, idx := range included.Indexes {
			armIdx := &armcosmos.Indexes{Precision: idx.Precision}
			if idx.DataType != "" {
				armIdx.DataType = to.Ptr(armcosmos.DataType(idx.DataType))
			}
			if idx.Kind != "" {
				armIdx.Kind = to.Ptr(armcosmos.IndexKind(idx.Kind))
			}
			entry.Indexes = append(entry.Indexes, armIdx)
		}
		policy.IncludedPaths = append(policy.IncludedPaths, entry)
	}
	for _, excluded := range p.ExcludedPaths {
		policy.ExcludedPaths = append(policy.ExcludedPaths, &armcosmos.ExcludedPath{Path: to.Ptr(excluded.Path)})
	}
	for _, composite := range p.CompositeIndexes {
		group := make([]*armcosmos.CompositePath, 0, len(composite))
		for _, path := range composite {
			entry := &armcosmos.CompositePath{Path: to.Ptr(path.Path)}
			if path.Order != "" {
				entry.Order = to.Ptr(armcosmos.CompositePathSortOrder(path.Order))
			}
			group = append(group, entry)
		}
		policy.CompositeIndexes = append(policy.CompositeIndexes, group)
	}
	for _, spatial := range p.SpatialIndexes {
		entry := &armcosmos.SpatialSpec{Path: to.Ptr(spatial.Path)}
		for _, t := range spatial.Types {
			entry.Types = append(entry.Types, to.Ptr(armcosmos.SpatialType(t)))
		}
		policy.SpatialIndexes = append(policy.SpatialIndexes, entry)
	}
	return policy
}

func cosmosIndexingPolicyFromARM(policy *armcosmos.IndexingPolicy) map[string]any {
	if policy == nil {
		return nil
	}
	entry := map[string]any{}
	if policy.Automatic != nil {
		entry["automatic"] = *policy.Automatic
	}
	if policy.IndexingMode != nil {
		entry["indexingMode"] = canonicalizeEnum(string(*policy.IndexingMode), "consistent", "lazy", "none")
	}
	if included := cosmosIncludedPathsFromARM(policy.IncludedPaths); len(included) > 0 {
		entry["includedPaths"] = included
	}
	excluded := make([]map[string]any, 0, len(policy.ExcludedPaths))
	for _, path := range policy.ExcludedPaths {
		if path == nil || path.Path == nil {
			continue
		}
		excluded = append(excluded, map[string]any{"path": *path.Path})
	}
	if len(excluded) > 0 {
		entry["excludedPaths"] = excluded
	}
	composites := make([][]map[string]any, 0, len(policy.CompositeIndexes))
	for _, group := range policy.CompositeIndexes {
		rendered := make([]map[string]any, 0, len(group))
		for _, path := range group {
			if path == nil || path.Path == nil {
				continue
			}
			pathEntry := map[string]any{"path": *path.Path}
			if path.Order != nil {
				pathEntry["order"] = canonicalizeEnum(string(*path.Order), "ascending", "descending")
			}
			rendered = append(rendered, pathEntry)
		}
		if len(rendered) > 0 {
			composites = append(composites, rendered)
		}
	}
	if len(composites) > 0 {
		entry["compositeIndexes"] = composites
	}
	spatials := make([]map[string]any, 0, len(policy.SpatialIndexes))
	for _, spatial := range policy.SpatialIndexes {
		if spatial == nil || spatial.Path == nil {
			continue
		}
		spatialEntry := map[string]any{"path": *spatial.Path}
		types := make([]string, 0, len(spatial.Types))
		for _, t := range spatial.Types {
			if t == nil {
				continue
			}
			types = append(types, canonicalizeEnum(string(*t), "LineString", "MultiPolygon", "Point", "Polygon"))
		}
		if len(types) > 0 {
			spatialEntry["types"] = types
		}
		spatials = append(spatials, spatialEntry)
	}
	if len(spatials) > 0 {
		entry["spatialIndexes"] = spatials
	}
	if len(entry) == 0 {
		return nil
	}
	return entry
}

func cosmosIncludedPathsFromARM(paths []*armcosmos.IncludedPath) []map[string]any {
	out := make([]map[string]any, 0, len(paths))
	for _, path := range paths {
		if path == nil || path.Path == nil {
			continue
		}
		entry := map[string]any{"path": *path.Path}
		indexes := make([]map[string]any, 0, len(path.Indexes))
		for _, idx := range path.Indexes {
			if idx == nil {
				continue
			}
			idxEntry := map[string]any{}
			if idx.DataType != nil {
				idxEntry["dataType"] = canonicalizeEnum(string(*idx.DataType),
					"LineString", "MultiPolygon", "Number", "Point", "Polygon", "String")
			}
			if idx.Kind != nil {
				idxEntry["kind"] = canonicalizeEnum(string(*idx.Kind), "Hash", "Range", "Spatial")
			}
			if idx.Precision != nil {
				idxEntry["precision"] = *idx.Precision
			}
			if len(idxEntry) > 0 {
				indexes = append(indexes, idxEntry)
			}
		}
		if len(indexes) > 0 {
			entry["indexes"] = indexes
		}
		out = append(out, entry)
	}
	return out
}

func cosmosConflictResolutionPolicyToARM(p *cosmosConflictResolutionPolicyProps) *armcosmos.ConflictResolutionPolicy {
	if p == nil {
		return nil
	}
	policy := &armcosmos.ConflictResolutionPolicy{}
	if p.Mode != "" {
		policy.Mode = to.Ptr(armcosmos.ConflictResolutionMode(p.Mode))
	}
	if p.ConflictResolutionPath != "" {
		policy.ConflictResolutionPath = to.Ptr(p.ConflictResolutionPath)
	}
	if p.ConflictResolutionProcedure != "" {
		policy.ConflictResolutionProcedure = to.Ptr(p.ConflictResolutionProcedure)
	}
	return policy
}

func cosmosConflictResolutionPolicyFromARM(policy *armcosmos.ConflictResolutionPolicy) map[string]any {
	if policy == nil {
		return nil
	}
	entry := map[string]any{}
	if policy.Mode != nil {
		entry["mode"] = canonicalizeEnum(string(*policy.Mode), "Custom", "LastWriterWins")
	}
	// ARM echoes conflictResolutionPath as "" for Custom mode and
	// conflictResolutionProcedure as "" for LastWriterWins; emitting the empty
	// string would report drift against a fixture that omits the field.
	if policy.ConflictResolutionPath != nil && *policy.ConflictResolutionPath != "" {
		entry["conflictResolutionPath"] = *policy.ConflictResolutionPath
	}
	if policy.ConflictResolutionProcedure != nil && *policy.ConflictResolutionProcedure != "" {
		entry["conflictResolutionProcedure"] = *policy.ConflictResolutionProcedure
	}
	if len(entry) == 0 {
		return nil
	}
	return entry
}

func cosmosUniqueKeyPolicyToARM(p *cosmosUniqueKeyPolicyProps) *armcosmos.UniqueKeyPolicy {
	if p == nil {
		return nil
	}
	policy := &armcosmos.UniqueKeyPolicy{}
	for _, key := range p.UniqueKeys {
		policy.UniqueKeys = append(policy.UniqueKeys, &armcosmos.UniqueKey{Paths: stringPointers(key.Paths)})
	}
	return policy
}

func cosmosUniqueKeyPolicyFromARM(policy *armcosmos.UniqueKeyPolicy) map[string]any {
	if policy == nil {
		return nil
	}
	keys := make([]map[string]any, 0, len(policy.UniqueKeys))
	for _, key := range policy.UniqueKeys {
		if key == nil {
			continue
		}
		if paths := stringsFromPointers(key.Paths); len(paths) > 0 {
			keys = append(keys, map[string]any{"paths": paths})
		}
	}
	if len(keys) == 0 {
		return nil
	}
	return map[string]any{"uniqueKeys": keys}
}
