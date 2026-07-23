# Changelog

All notable changes to the formae Azure plugin are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Install with `sudo formae plugin install azure` on the host that runs the
formae agent.

## [0.1.10]

Ingress/TLS resources — terminate HTTPS at a managed Azure ingress, manage the
certificate and DNS, and (optionally) run the workload on Container Apps.

### Added

- `KeyVault::Certificate`. Data-plane certificate lifecycle (vaultUri-based, like
  `KeyVault::Secret`): import a BYO PFX/PEM (`data` + `password`, write-only) or
  issue a self-signed cert via a minimal `policy` (issuerName / subject / keyType
  / validityMonths). The resolvable exposes `id`, `secretId`, and `thumbprint`, so
  `secretId` can be wired into an Application Gateway or Front Door listener.
- `Network::ApplicationGatewayWebApplicationFirewallPolicy` — WAF policy
  (policySettings, managed OWASP rule sets, custom rules). Attach it to an
  Application Gateway via the new `firewallPolicyId` field on
  `Network::ApplicationGateway`.
- `Network::DnsZone` and `Network::DnsRecordSet` — public DNS. One polymorphic
  record-set resource covers A / CNAME / TXT via `recordType`.
- Azure Front Door Standard family (`Microsoft.Cdn`): `Cdn::Profile`,
  `Cdn::AFDEndpoint`, `Cdn::AFDOriginGroup`, `Cdn::AFDOrigin`, `Cdn::Route`,
  `Cdn::AFDCustomDomain`, and `Cdn::Secret` (BYO Key Vault TLS certificate).
- Azure Container Apps (`Microsoft.App`): `App::ManagedEnvironment` and
  `App::ContainerApp` (ingress, containers, scale; secrets are write-only).
- `Network::ApplicationGateway` `sslCertificates[].keyVaultSecretId` now accepts a
  resolvable, so a listener can point at a `KeyVault::Certificate`'s `secretId`.

### Changed

- Long-running-operation failures now carry the underlying provider error in
  `StatusMessage`, so a retrying resource reports *why* it failed instead of a
  bare error code.
- The per-subscription Azure client is now built under a per-subscription lock
  rather than the global cache lock, so a cold apply burst no longer serializes
  every operation behind one credential/client construction.
- Conformance matrix (CI + nightly) extended with the new resources, with widened
  timeouts for the slow Front Door (`cdn-*`) lane. `cdn-route` is excluded pending
  a formae-core resolve-cache fix; `certificate`, `cdn-afd-custom-domain`,
  `cdn-secret`, `managed-environment`, and `container-app` are excluded because
  they need a real certificate/domain/data-plane role or are too slow to
  provision in CI — all are covered by mocked integration + marshaller round-trip
  tests and a manual live gate.

### Fixed

- Zero-drift read-back for the new resources: the WAF custom-rule
  `negationConditon` default, Front Door provider-defaulted optional fields,
  Front Door's canonical `location` (`"Global"`), and the Application Gateway
  managed-identity `type` casing (`userAssigned` → `UserAssigned`) no longer
  reconcile as phantom updates.

## [0.1.6]

### Added

- `KeyVault::Secret`. Manage a secret inside an existing Key Vault, parented to a
  `KeyVault::Vault` through its `vaultUri`. The secret value is write-only and
  uses formae's opaque values, so it is masked in diffs and stored as a hash
  rather than in cleartext: `formae.value(x).opaque` rotates the secret in place
  when its value changes, while `formae.value(x).opaque.setOnce` seeds the secret
  once and leaves it untouched on later edits to that value. Requires formae
  0.86.2 or later, so an unchanged secret is not re-written when other fields on
  the same resource change.

## [0.1.5]

### Added

- Azure SQL support: `Sql::Server`, `Sql::Database`, `Sql::FirewallRule`, and
  `Sql::ServerAzureADAdministrator`. Provision a logical SQL server together with
  its databases, firewall rules, and Azure AD administrator from a single forma.
- Workload identity federation end to end. `ManagedCluster` now exposes
  `oidcIssuerUrl` and `UserAssignedIdentity` exposes `tenantId` through their
  resolvables, and `FederatedIdentityCredential.issuer` accepts a resolvable.
  Together these let you create an AKS cluster, a user-assigned identity, and the
  federated credential linking them in one forma.

### Fixed

- Provider-immutable fields on `Authorization::RoleAssignment`,
  `Compute::VirtualMachine`, `ContainerService::ManagedCluster`,
  `ContainerService::TrustedAccessRoleBinding`,
  `KubernetesConfiguration::Extension`, and
  `KubernetesConfiguration::FluxConfiguration` are now marked create-only, so
  changing them plans a replace instead of attempting an update the provider
  would reject. Requires formae 0.86.0 or later.

## [0.1.4]

### Added

- Nine resources for private workload patterns: `Network::LoadBalancer`,
  `Network::PrivateEndpoint`, `Network::PrivateDnsZone`,
  `Network::PrivateDnsZoneVirtualNetworkLink`, `Network::PrivateDnsZoneGroup`,
  `Compute::Disk`, `Compute::VirtualMachineScaleSet`, `Storage::BlobContainer`,
  and `ManagedIdentity::FederatedIdentityCredential`. Enables provisioning
  private-endpoint-fronted services (private DNS zones linked to VNets, app-side
  private endpoints) and scaled compute backed by managed disks.

### Changed

- Resource type identifiers now use uppercase `AZURE::` instead of `Azure::`
  (e.g. `AZURE::Network::VirtualNetwork`,
  `AZURE::ContainerService::ManagedCluster`). Aligns with the casing used by the
  AWS, GCP, and OCI plugins. CLI filters or queries that reference Azure resource
  types by string need updating; resources already in inventory under the old
  casing should be re-discovered after upgrade.

## [0.1.2]

### Added

- AKS sub-resource support. `MaintenanceConfiguration`, `Extension`,
  `FluxConfiguration`, and `TrustedAccessRoleBinding` can now be managed
  alongside `ManagedCluster`. Use these for AKS maintenance windows, Kubernetes
  extensions (Flux, Dapr, Azure ML), GitOps Flux v2 configuration, and granting
  Azure services access to an AKS cluster.
- `ManagedCluster` now exposes `kubeConfig` and the cluster CA certificate
  through its `res` resolvable. This lets you provision an AKS cluster and deploy
  Kubernetes workloads onto it from the same forma without a manual kubeconfig
  step, the same pattern as EKS auth via resolvables.

## [0.1.1]

### Fixed

- Error responses from the Azure API now include the correct HTTP status code,
  improving error messages when operations fail.
- Apply and sync no longer fail on resources with empty optional arrays or maps
  in their schema.

## [0.1.0]

### Added

- Initial release of the Azure plugin as a standalone package built on the formae
  Plugin SDK.
