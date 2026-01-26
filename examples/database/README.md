# Database

Managed PostgreSQL database in Azure.

## What You Get

- Resource Group
- PostgreSQL Flexible Server (Postgres 16, Burstable tier)
- Firewall Rules (your IP + Azure services)

## Prerequisites

1. Azure CLI authenticated: `az login`
2. Valid Azure subscription
3. `psql` client

## Configuration

Edit `vars.pkl`:

```pkl
subscriptionId = read?("env:AZURE_SUBSCRIPTION_ID") ?? "your-subscription-id"
myIpAddress = read?("env:MY_IP") ?? "your.ip.here"
adminPassword = read?("env:POSTGRES_PASSWORD") ?? "ChangeMe123!"
```

## Deploy

```bash
formae apply main.pkl
formae status command --watch --output-layout detailed
```

## Test the Connection

```bash
PGPASSWORD="ChangeMe123!" psql \
  "host=azure-database-pg.postgres.database.azure.com \
   port=5432 dbname=postgres user=pgadmin sslmode=require" \
  -c "SELECT version();"
```

## Tear Down

```bash
formae destroy --query 'stack:azure-database-eastus' --yes
```

## Architecture

```
Resource Group (azure-database-rg)
└── PostgreSQL Flexible Server (azure-database-pg)
    ├── Firewall Rule: AllowMyIP (your IP)
    └── Firewall Rule: AllowAzureServices (0.0.0.0)
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Connection refused | Check your IP hasn't changed (`curl ifconfig.me`) |
| Auth failed | Verify password in `vars.pkl` matches what you're using |
| Resource not found | Wait for apply to complete; Postgres takes 5-10 minutes to provision |
