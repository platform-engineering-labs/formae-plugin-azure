# Changelog

All notable changes to the formae Azure plugin are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Install with `sudo formae plugin install azure` on the host that runs the
formae agent.

## [Unreleased]

### Added

- **25 new resource types**, taking the plugin from 148 to 173.
  - **Microsoft.Web (7)** — `Web::ServicePlan`, `Web::WebApp`, `Web::FunctionApp`,
    `Web::WebAppSlot`, `Web::Certificate`, `Web::CustomHostnameBinding`,
    `Web::StaticSite`. The plugin had no PaaS compute coverage at all before this.
  - **Cosmos DB children (11)** — `DocumentDB::Sql{Database,Container,RoleDefinition,RoleAssignment}`,
    `DocumentDB::Mongo{Database,Collection}`, `DocumentDB::Cassandra{Keyspace,Table}`,
    `DocumentDB::Gremlin{Database,Graph}`, `DocumentDB::Table`. The account type
    already existed but none of its per-API child resources did, so it could not
    express a usable database.
  - **Virtual WAN, gateways and Bastion (7)** — `Network::VirtualWan`,
    `Network::VirtualHub`, `Network::VpnGateway`, `Network::VpnSite`,
    `Network::VirtualNetworkGateway`, `Network::VirtualNetworkGatewayConnection`,
    `Network::BastionHost`. First hybrid-connectivity coverage in the plugin.
- `DocumentDB::DatabaseAccount` gained `capabilities`. Cassandra, Gremlin and Table
  children cannot be declared without it — `kind` only separates NoSQL from MongoDB,
  and the API family comes from a capability.
- Conformance now runs on pull requests, scoped to the fixtures the PR changed, so a
  new fixture is verified before it reaches main instead of after.
- A scheduled reaper sweeps leaked conformance resource groups every 6 hours.

### Fixed

- `Network::VirtualHub` delete no longer fails while the hub router is still
  programming. ARM refuses `DeleteVirtualHub` while `routingState` is
  `Provisioning`, which runs ~11 minutes past the point the create LRO reports
  `Succeeded`; the delete now waits for the router instead of erroring.
- Conformance cleanup verifies its deletions instead of firing and forgetting. It
  previously ran `az group delete --no-wait || true` and reported success
  unconditionally, so a refused delete or a group created mid-sweep leaked silently.


### Changed

- `KeyVault::Secret` Read now includes the secret value in the returned properties,
  enabling the `value` resolvable to resolve for downstream resources. The value is
  protected at rest by formae's `SecretValue` hashing (introduced in v0.1.9).

## [0.1.10]

### Changed

- Bump examples to the latest formae 0.88.0 schema.

## [0.1.9]

### Changed

- Genuine secret-value fields are now typed `formae.SecretValue` so their values are hashed at rest end-to-end (previously stored in cleartext on the read/actual-state path). Covers `Azure::Compute::VirtualMachine` and `Azure::Compute::VirtualMachineScaleSet` `adminPassword`, `Azure::DBforPostgreSQL::FlexibleServer` and `Azure::Sql::Server` `administratorLoginPassword`, `Azure::KeyVault::Secret` `value`, and `Azure::KubernetesConfiguration::FluxConfiguration` `accessKey`. Requires a formae agent on the matching release; `minFormaeVersion` is bumped to 0.88.0.

## [0.1.8]

Managed HTTPS ingress on Azure — an Application Gateway (optionally WAF-fronted)
or Front Door terminating TLS, the certificate and DNS to go with it,
per-subscription credential caching, and (optionally) running the workload on
Container Apps.

### Added

- `Network::ApplicationGateway` — Application Gateway v2 (L7 load balancer / HTTPS
  ingress): gateway/frontend IP configurations, frontend ports, backend address
  pools, backend HTTP settings, health probes, HTTP listeners, request routing
  rules, SSL certificates (inline PFX or a Key Vault secret reference), an optional
  user-assigned managed identity, and a `firewallPolicyId` to attach a WAF policy.
- `Network::ApplicationGatewayWebApplicationFirewallPolicy` — WAF policy
  (policySettings, managed OWASP rule sets, custom rules).
- `KeyVault::Certificate`. Data-plane certificate lifecycle (vaultUri-based, like
  `KeyVault::Secret`): import a BYO PFX/PEM (`data` + `password`, write-only) or
  issue a self-signed cert via a minimal `policy` (issuerName / subject / keyType
  / validityMonths). The resolvable exposes `id`, `secretId`, and `thumbprint`, so
  `secretId` can be wired into an Application Gateway or Front Door listener.
- `Network::DnsZone` and `Network::DnsRecordSet` — public DNS. One polymorphic
  record-set resource covers A / CNAME / TXT via `recordType`.
- Azure Front Door Standard family (`Microsoft.Cdn`): `Cdn::Profile`,
  `Cdn::AFDEndpoint`, `Cdn::AFDOriginGroup`, `Cdn::AFDOrigin`, `Cdn::Route`,
  `Cdn::AFDCustomDomain`, and `Cdn::Secret` (BYO Key Vault TLS certificate).
- Azure Container Apps (`Microsoft.App`): `App::ManagedEnvironment` and
  `App::ContainerApp` (ingress, containers, scale; secrets are write-only).

### Changed

- The Azure client and its credential are now cached per subscription for the
  plugin process lifetime instead of being rebuilt on every operation — a token
  is acquired once (while fresh) and reused, which fixes short-lived federated-auth
  failures (e.g. GitHub OIDC in CI, where rebuilding the credential per operation
  re-exchanges an assertion that has since expired). The cached client is built
  under a per-subscription lock, so a cold apply burst does not serialize every
  operation behind one credential/client construction.
- Long-running-operation failures now carry the underlying provider error in
  `StatusMessage`, so a retrying resource reports *why* it failed instead of a
  bare error code.
- Conformance matrix (CI + nightly) extended with the new resources, with widened
  timeouts for the slow Front Door (`cdn-*`) lane. `cdn-route` is excluded pending
  a formae-core resolve-cache fix; `certificate`, `cdn-afd-custom-domain`,
  `cdn-secret`, `managed-environment`, and `container-app` are excluded because
  they need a real certificate/domain/data-plane role or are too slow to provision
  in CI — all covered by mocked integration + marshaller round-trip tests and a
  manual live gate.

### Fixed

- Zero-drift read-back for the ingress resources: the WAF custom-rule
  `negationConditon` default, Front Door provider-defaulted optional fields, Front
  Door's canonical `location` (`"Global"`), and the Application Gateway
  managed-identity `type` casing (`userAssigned` → `UserAssigned`) no longer
  reconcile as phantom updates.

## [0.1.7]

### Added

- Eight resource types to shore up common Azure coverage:
  `CognitiveServices::Account`, `Compute::VirtualMachineExtension`,
  `Dashboard::Grafana`, `Dashboard::GrafanaManagedPrivateEndpoint`,
  `EventGrid::SystemTopic`, `EventHub::Namespace`, `Network::RouteTable`, and
  `ServiceBus::Namespace`.

### Fixed

- `Compute::VirtualMachine` now serializes SSH public keys on Read, and its OS /
  configuration fields are marked create-only, so changing an immutable field
  plans a replace instead of an update the provider would reject.

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
