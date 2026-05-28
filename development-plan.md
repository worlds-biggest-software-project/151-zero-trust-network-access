# Zero Trust Network Access — Phased Development Plan

> Project: 151-zero-trust-network-access · Created: 2026-05-25
> Purpose: Provide sufficient detail for Claude Code (Opus) to implement each phase end-to-end.

---

## Technology Decisions & Rationale

### Language & Runtime
- **Control Plane: Go 1.23+** — Rationale: Go dominates infrastructure security tooling (Teleport, Boundary, OpenZiti, Tailscale, NetBird are all Go). Goroutines provide efficient concurrent session handling. Strong standard library for TLS, X.509 certificates, and networking. Cross-compilation to static binaries simplifies connector deployment. Memory-safe without GC pauses for latency-sensitive policy evaluation.
- **Policy Decision Engine: Go with embedded OPA (Open Policy Agent)** — Rationale: OPA's Rego language is the industry standard for infrastructure policy evaluation (used by Styra, Kubernetes admission controllers). Embedding OPA via the Go SDK avoids a separate process and keeps policy evaluation <5ms. Policies are authored as Rego and stored alongside JSONB representations.
- **Management API: Go with Chi router** — lightweight, stdlib-compatible HTTP router. OpenAPI 3.1 spec generated from Go structs via oapi-codegen.
- **Frontend Dashboard: TypeScript + React 19 with Next.js 15** — Rationale: industry-standard for SaaS dashboards; Server Components for data-heavy session tables and audit log views.
- **CLI: Go (Cobra)** — for admin operations, connector management, and developer tooling.
- **Connector Agent: Go** — lightweight binary deployed in customer networks; outbound-only connections via gRPC/mTLS.

### Data Model
- **Hybrid Relational + JSONB (Data Model Suggestion 3) as the primary model, with the graph query patterns from Suggestion 4 for blast radius and trust chain analysis.** Rationale:
  - The Hybrid model (Suggestion 3) provides the fastest MVP path: typed columns for high-cardinality joins (users, devices, sessions), JSONB for variable policy rules, posture signals, and IdP-specific claims. This matches how Cloudflare, Zscaler, and Tailscale model their policy APIs (nested JSON).
  - From Suggestion 4, we adopt: (a) the `graph_edges` table with temporal validity for relationship queries (blast radius, trust chains, conflict-of-interest detection), (b) `ltree` for network segment hierarchy, (c) `org_units` with hierarchical paths.
  - We do NOT adopt full event sourcing (Suggestion 2) because the added CQRS complexity delays MVP. Instead, we implement immutable append-only audit tables (from Suggestion 1's `audit_events` pattern) with OCSF classification.
  - We do NOT adopt pure normalized relational (Suggestion 1) because new posture signals and compliance-specific policy conditions would require schema migrations for every deployment variation.

### Database
- **PostgreSQL 16** — Rationale: JSONB with GIN indexes for policy rules, Row Level Security for multi-tenancy, ltree extension for network/org hierarchies, CIDR type for network segments, partitioning for audit/decision logs, triggers for graph edge maintenance. All four data model suggestions are PostgreSQL-native.
- **Redis 7** — Rationale: session token cache, connector heartbeat tracking, real-time risk score updates, pub/sub for session state changes.

### Identity & Authentication
- **OAuth 2.0 with PKCE + OIDC + SAML 2.0** — Rationale: NIST SP 800-207 requires identity verification on every access request. Must support major IdPs (Okta, Azure AD, Google Workspace). SAML required for enterprise customers.
- **FIDO2/WebAuthn** — Rationale: phishing-resistant MFA per NIST SP 800-63B AAL2/AAL3. Required for FedRAMP compliance.
- **SPIFFE/SPIRE** — Rationale: CNCF-graduated standard for workload identity. X.509 SVIDs with 1-hour lifetime for service-to-service zero trust.

### Connector Transport
- **gRPC with mTLS** — Rationale: bidirectional streaming for real-time session events; mTLS ensures connector-to-control-plane authentication without shared secrets. Certificate-based identity aligns with NIST SP 800-207 PEP model.
- **WireGuard** — Rationale: modern tunnelling protocol for data-plane traffic between connector and client; used by NetBird, Tailscale, and OpenZiti.

### AI / LLM Layer
- **Model-agnostic via an LLM abstraction layer** — support Claude (Anthropic SDK), GPT-4o (OpenAI SDK), and local models via Ollama. Rationale: avoids vendor lock-in; self-hosted deployments must work without cloud LLM dependencies.
- **Scikit-learn + custom Go models** — Rationale: behavioral baselining and anomaly detection run as lightweight statistical models (isolation forest, time-series deviation), not LLM calls. Keeps detection latency <10ms.

### Deployment
- **Docker Compose for development, Kubernetes for production** — self-hostable as a core requirement.
- **Helm chart** — for Kubernetes deployment with sensible defaults.
- **S3-compatible object storage** — for session recordings, certificate backups, and audit log exports.

### Licence
- **Apache 2.0** for the core platform and connector. Rationale: matches Teleport, OpenZiti, and Boundary licensing; maximises adoption without copyleft concerns. The most successful open-source ZTNA projects all use permissive licences.

---

## Project Structure

```
151-zero-trust-network-access/
├── cmd/
│   ├── control-plane/
│   │   └── main.go                    # Control plane entry point
│   ├── connector/
│   │   └── main.go                    # Connector agent entry point
│   └── ztna-cli/
│       └── main.go                    # CLI tool entry point
├── internal/
│   ├── config/
│   │   └── config.go                  # Configuration (Viper)
│   ├── db/
│   │   ├── postgres.go                # PostgreSQL connection pool
│   │   ├── redis.go                   # Redis client
│   │   ├── rls.go                     # Row Level Security helpers
│   │   └── migrations/               # golang-migrate migration files
│   │       ├── 001_foundation.up.sql
│   │       ├── 001_foundation.down.sql
│   │       └── ...
│   ├── models/                        # Database models (sqlc generated)
│   │   ├── tenant.go
│   │   ├── user.go
│   │   ├── device.go
│   │   ├── application.go
│   │   ├── connector.go
│   │   ├── policy.go
│   │   ├── session.go
│   │   ├── audit.go
│   │   └── graph.go
│   ├── api/                           # REST API handlers
│   │   ├── v1/
│   │   │   ├── router.go
│   │   │   ├── tenants.go
│   │   │   ├── users.go
│   │   │   ├── devices.go
│   │   │   ├── applications.go
│   │   │   ├── connectors.go
│   │   │   ├── policies.go
│   │   │   ├── sessions.go
│   │   │   ├── audit.go
│   │   │   └── dashboard.go
│   │   ├── middleware/
│   │   │   ├── auth.go
│   │   │   ├── rls.go
│   │   │   ├── ratelimit.go
│   │   │   └── logging.go
│   │   └── openapi.go                 # OpenAPI spec generation
│   ├── auth/                          # Authentication providers
│   │   ├── oidc.go
│   │   ├── saml.go
│   │   ├── webauthn.go
│   │   └── token.go                   # JWT issuance and validation
│   ├── policy/                        # Policy Decision Point (PDP)
│   │   ├── engine.go                  # OPA-based policy evaluation
│   │   ├── evaluator.go              # Rule evaluation logic
│   │   ├── rego/                      # Rego policy definitions
│   │   │   ├── access.rego
│   │   │   ├── posture.rego
│   │   │   └── compliance.rego
│   │   └── compiler.go               # Rego compilation and caching
│   ├── posture/                       # Device posture assessment
│   │   ├── checker.go
│   │   ├── signals.go
│   │   └── compliance.go
│   ├── session/                       # Session management
│   │   ├── manager.go
│   │   ├── verifier.go               # Continuous verification
│   │   ├── recorder.go               # Session recording
│   │   └── token.go
│   ├── connector/                     # Connector management
│   │   ├── registry.go
│   │   ├── heartbeat.go
│   │   └── tunnel.go
│   ├── transport/                     # Data plane transport
│   │   ├── grpc/
│   │   │   ├── server.go
│   │   │   ├── client.go
│   │   │   └── proto/
│   │   │       ├── connector.proto
│   │   │       └── session.proto
│   │   └── wireguard/
│   │       ├── interface.go
│   │       └── peer.go
│   ├── graph/                         # Graph query layer
│   │   ├── nodes.go
│   │   ├── edges.go
│   │   ├── traversal.go              # BFS/DFS for blast radius
│   │   └── sync.go                   # Relational-to-graph sync
│   ├── ai/                            # AI / ML layer
│   │   ├── llm/
│   │   │   ├── client.go             # Model-agnostic LLM abstraction
│   │   │   ├── policy_generator.go   # AI policy generation
│   │   │   └── nl_policy.go          # Natural language policy authoring
│   │   ├── anomaly/
│   │   │   ├── baseline.go           # Behavioral baselining
│   │   │   ├── detector.go           # Real-time anomaly detection
│   │   │   └── risk_scorer.go        # Adaptive risk scoring
│   │   └── remediation/
│   │       └── agent.go              # Automated remediation
│   ├── audit/                         # Audit & compliance
│   │   ├── logger.go                 # OCSF-aligned audit logging
│   │   ├── ocsf.go                   # OCSF event mapping
│   │   └── export.go                 # SIEM export (S3, Splunk)
│   └── pki/                           # Certificate management
│       ├── ca.go                      # Internal CA
│       ├── spiffe.go                 # SPIFFE SVID issuance
│       └── rotation.go              # Certificate rotation
├── proto/                             # Protobuf definitions
│   ├── connector/v1/
│   └── session/v1/
├── frontend/
│   ├── src/
│   │   ├── app/                       # Next.js App Router
│   │   │   ├── dashboard/
│   │   │   ├── policies/
│   │   │   ├── sessions/
│   │   │   ├── devices/
│   │   │   ├── applications/
│   │   │   ├── connectors/
│   │   │   ├── audit/
│   │   │   └── settings/
│   │   ├── components/
│   │   │   ├── ui/                    # Shadcn/ui components
│   │   │   ├── policies/
│   │   │   ├── sessions/
│   │   │   └── charts/
│   │   ├── hooks/
│   │   ├── lib/
│   │   │   ├── api-client.ts
│   │   │   └── auth.ts
│   │   └── types/
│   │       └── api.ts                 # Generated from OpenAPI
│   ├── package.json
│   ├── tsconfig.json
│   └── Dockerfile
├── deploy/
│   ├── docker-compose.yml
│   ├── docker-compose.prod.yml
│   ├── helm/
│   │   └── ztna/
│   │       ├── Chart.yaml
│   │       ├── values.yaml
│   │       └── templates/
│   └── terraform/                     # Example cloud deployments
├── docs/
│   ├── architecture.md
│   └── api-reference.md
├── tests/
│   ├── integration/
│   ├── e2e/
│   └── load/
├── .env.example
├── Makefile
├── go.mod
├── go.sum
└── README.md
```

---

## Phase Dependency Graph

```
Phase 1: Foundation
    │
    ├──▶ Phase 2: Identity & Device Trust
    │        │
    │        ├──▶ Phase 3: Policy Engine (PDP/PEP)
    │        │        │
    │        │        ├──▶ Phase 4: Connector & Data Plane
    │        │        │        │
    │        │        │        └──▶ Phase 5: Session Management & Continuous Verification
    │        │        │                 │
    │        │        │                 └──▶ Phase 6: Session Recording & Audit
    │        │        │
    │        │        └──▶ Phase 7: Multi-Cloud & Network Topology
    │        │
    │        └──▶ Phase 8: AI Anomaly Detection & Risk Scoring
    │
    ├──▶ Phase 9: Frontend Dashboard (can start after Phase 2, iterates with each phase)
    │
    ├──▶ Phase 10: AI Policy Generation & Natural Language Authoring
    │        │
    │        └──▶ Phase 11: Compliance Templates & Reporting
    │
    └──▶ Phase 12: Production Hardening & Deployment
```

**Critical path:** Phase 1 → 2 → 3 → 4 → 5 (live session management depends on policy engine and connector transport).
**Parallel work:** Phase 8 (AI anomaly detection) and Phase 9 (frontend) can proceed in parallel with Phases 4-5 once Phase 2/3 are complete. Phase 10 (AI policy generation) can begin once Phase 3 (policy engine) is stable.

---

## Phase 1: Foundation — Project Scaffolding, Database, Multi-Tenancy

### Definition of Done
- Go control plane application boots and serves a health endpoint.
- PostgreSQL database is provisioned with multi-tenancy via Row Level Security.
- Redis is provisioned for caching and pub/sub.
- Tenant CRUD works with RLS enforced.
- Docker Compose runs the full stack locally.
- CI pipeline runs tests on every push.

### Task 1.1: Project Scaffolding & Configuration

**What:** Create the Go backend project with Chi router, configure dependency management, and set up the development environment.

**Design:**

```go
// internal/config/config.go
package config

import "github.com/spf13/viper"

type Config struct {
    AppName     string `mapstructure:"app_name"`
    Environment string `mapstructure:"environment"` // development, staging, production
    Debug       bool   `mapstructure:"debug"`

    // Server
    HTTPPort int    `mapstructure:"http_port"`
    GRPCPort int    `mapstructure:"grpc_port"`
    TLSCert  string `mapstructure:"tls_cert"`
    TLSKey   string `mapstructure:"tls_key"`

    // Database
    DatabaseURL      string `mapstructure:"database_url"`
    DatabasePoolSize int    `mapstructure:"database_pool_size"`

    // Redis
    RedisURL string `mapstructure:"redis_url"`

    // Auth
    OIDCIssuerURL string `mapstructure:"oidc_issuer_url"`
    OIDCClientID  string `mapstructure:"oidc_client_id"`
    OIDCAudience  string `mapstructure:"oidc_audience"`

    // PKI
    CAKeyRef string `mapstructure:"ca_key_ref"` // KMS reference for CA private key
    CACert   string `mapstructure:"ca_cert"`

    // LLM
    LLMProvider string `mapstructure:"llm_provider"` // anthropic, openai, ollama
    LLMAPIKey   string `mapstructure:"llm_api_key"`
    LLMModel    string `mapstructure:"llm_model"`

    // Storage
    S3Bucket      string `mapstructure:"s3_bucket"`
    S3EndpointURL string `mapstructure:"s3_endpoint_url"`
}

func Load() (*Config, error) {
    viper.SetConfigName("config")
    viper.SetConfigType("yaml")
    viper.AddConfigPath(".")
    viper.AddConfigPath("/etc/ztna/")
    viper.SetEnvPrefix("ZTNA")
    viper.AutomaticEnv()

    var cfg Config
    if err := viper.ReadInConfig(); err != nil {
        // Config file not found; rely on env vars
    }
    if err := viper.Unmarshal(&cfg); err != nil {
        return nil, err
    }
    return &cfg, nil
}
```

```go
// cmd/control-plane/main.go
package main

import (
    "context"
    "log/slog"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/go-chi/chi/v5"
    chimiddleware "github.com/go-chi/chi/v5/middleware"
    "ztna/internal/config"
    "ztna/internal/db"
)

func main() {
    cfg, err := config.Load()
    if err != nil {
        slog.Error("failed to load config", "error", err)
        os.Exit(1)
    }

    pool, err := db.NewPostgresPool(cfg.DatabaseURL, cfg.DatabasePoolSize)
    if err != nil {
        slog.Error("failed to connect to database", "error", err)
        os.Exit(1)
    }
    defer pool.Close()

    r := chi.NewRouter()
    r.Use(chimiddleware.RequestID)
    r.Use(chimiddleware.RealIP)
    r.Use(chimiddleware.Logger)
    r.Use(chimiddleware.Recoverer)

    r.Get("/api/health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"status":"ok","version":"0.1.0"}`))
    })

    srv := &http.Server{
        Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
        Handler:      r,
        ReadTimeout:  15 * time.Second,
        WriteTimeout: 15 * time.Second,
        IdleTimeout:  60 * time.Second,
    }

    go func() {
        slog.Info("starting control plane", "port", cfg.HTTPPort)
        if err := srv.ListenAndServe(); err != http.ErrServerClosed {
            slog.Error("server error", "error", err)
        }
    }()

    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    srv.Shutdown(ctx)
}
```

**Testing:**
- `TestHealthEndpointReturnsOK` — GET /api/health returns 200 with `{"status":"ok"}`.
- `TestConfigLoadsFromEnv` — Config correctly reads from environment variables with ZTNA_ prefix.
- `TestConfigDefaultValues` — Unset values use sensible defaults (port 8080, pool size 20).
- `TestGracefulShutdown` — Server drains connections on SIGTERM within 30 seconds.

### Task 1.2: Database Connection & Multi-Tenancy

**What:** Set up PostgreSQL connection pool with pgx, implement Row Level Security for multi-tenancy, create the tenants table and migration framework.

**Design:**

```go
// internal/db/postgres.go
package db

import (
    "context"
    "fmt"

    "github.com/jackc/pgx/v5/pgxpool"
)

func NewPostgresPool(databaseURL string, poolSize int) (*pgxpool.Pool, error) {
    config, err := pgxpool.ParseConfig(databaseURL)
    if err != nil {
        return nil, fmt.Errorf("parse database URL: %w", err)
    }
    config.MaxConns = int32(poolSize)
    config.MinConns = int32(poolSize / 4)

    pool, err := pgxpool.NewWithConfig(context.Background(), config)
    if err != nil {
        return nil, fmt.Errorf("create pool: %w", err)
    }

    if err := pool.Ping(context.Background()); err != nil {
        return nil, fmt.Errorf("ping database: %w", err)
    }
    return pool, nil
}

// internal/db/rls.go
package db

import (
    "context"
    "fmt"
    "github.com/google/uuid"
    "github.com/jackc/pgx/v5"
)

// SetTenantContext sets the current tenant for Row Level Security policies.
func SetTenantContext(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
    _, err := tx.Exec(ctx, fmt.Sprintf("SET LOCAL app.current_tenant_id = '%s'", tenantID.String()))
    return err
}
```

```sql
-- migrations/001_foundation.up.sql

-- RLS helper function
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID AS $$
    SELECT NULLIF(current_setting('app.current_tenant_id', TRUE), '')::UUID;
$$ LANGUAGE SQL STABLE;

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS ltree;
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Tenants table
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) NOT NULL UNIQUE,
    plan            VARCHAR(50) NOT NULL DEFAULT 'free'
                    CHECK (plan IN ('free', 'starter', 'business', 'enterprise')),
    settings        JSONB NOT NULL DEFAULT '{}',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Service accounts (API keys for automation)
CREATE TABLE service_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    api_key_hash    VARCHAR(128) NOT NULL,
    scopes          TEXT[] NOT NULL DEFAULT '{}',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE service_accounts ENABLE ROW LEVEL SECURITY;
CREATE POLICY sa_isolation ON service_accounts
    USING (tenant_id = current_tenant_id());
CREATE INDEX idx_sa_tenant ON service_accounts(tenant_id);
```

**Testing:**
- `TestRLSPreventsCrossTenantAccess` — Tenant A cannot read Tenant B's service accounts.
- `TestSetTenantContext` — `current_tenant_id()` returns the correct UUID after SET LOCAL.
- `TestConnectionPoolCreation` — Pool is created with correct min/max connections.
- `TestMigrationAppliesCleanly` — Migration 001 applies without errors on a fresh database.
- `TestMigrationRollback` — Down migration removes all tables cleanly.

### Task 1.3: Tenant CRUD API

**What:** Implement REST API for tenant management, including creation, retrieval, and settings updates.

**Design:**

```go
// internal/api/v1/tenants.go
package v1

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/go-chi/chi/v5"
    "github.com/google/uuid"
)

type TenantCreate struct {
    Name string `json:"name" validate:"required,min=2,max=255"`
    Slug string `json:"slug" validate:"required,min=2,max=100,alphanum"`
    Plan string `json:"plan,omitempty" validate:"omitempty,oneof=free starter business enterprise"`
}

type TenantResponse struct {
    ID        uuid.UUID              `json:"id"`
    Name      string                 `json:"name"`
    Slug      string                 `json:"slug"`
    Plan      string                 `json:"plan"`
    Settings  map[string]interface{} `json:"settings"`
    IsActive  bool                   `json:"is_active"`
    CreatedAt time.Time              `json:"created_at"`
    UpdatedAt time.Time              `json:"updated_at"`
}

func (h *Handler) CreateTenant(w http.ResponseWriter, r *http.Request) {
    var req TenantCreate
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        httpError(w, http.StatusBadRequest, "invalid request body")
        return
    }
    // Validate, insert, return response
}

func (h *Handler) GetTenant(w http.ResponseWriter, r *http.Request) {
    tenantID := chi.URLParam(r, "tenantID")
    // Fetch by ID with RLS
}

func (h *Handler) UpdateTenantSettings(w http.ResponseWriter, r *http.Request) {
    // Merge JSONB settings
}
```

**Testing:**
- `TestCreateTenantSuccess` — POST /api/v1/tenants creates tenant and returns 201.
- `TestCreateTenantDuplicateSlug` — Duplicate slug returns 409 Conflict.
- `TestCreateTenantValidation` — Missing name returns 400 with validation errors.
- `TestGetTenantByID` — GET /api/v1/tenants/{id} returns tenant details.
- `TestUpdateTenantSettings` — PATCH /api/v1/tenants/{id}/settings merges JSONB correctly.

### Task 1.4: Docker Compose & CI Setup

**What:** Create Docker Compose for local development (control plane, PostgreSQL, Redis), Makefile for common commands, and GitHub Actions CI pipeline.

**Design:**

```yaml
# deploy/docker-compose.yml
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: ztna
      POSTGRES_USER: ztna
      POSTGRES_PASSWORD: ztna_dev
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ztna"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s

  control-plane:
    build:
      context: ../
      dockerfile: cmd/control-plane/Dockerfile
    ports:
      - "8080:8080"
      - "9090:9090"
    environment:
      ZTNA_DATABASE_URL: "postgres://ztna:ztna_dev@db:5432/ztna?sslmode=disable"
      ZTNA_REDIS_URL: "redis://redis:6379"
      ZTNA_HTTP_PORT: "8080"
      ZTNA_GRPC_PORT: "9090"
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy

volumes:
  pgdata:
```

**Testing:**
- `TestDockerComposeBoot` — `docker compose up` brings all services to healthy state.
- `TestMakefileTargets` — `make test`, `make lint`, `make build` all succeed.
- `TestCIPipelineConfig` — GitHub Actions workflow is valid YAML with correct job dependencies.

---

## Phase 2: Identity & Device Trust

### Definition of Done
- OIDC and SAML identity provider integration works end-to-end.
- User registration, authentication, and group sync from IdP complete.
- Device registration and posture assessment pipeline operational.
- FIDO2/WebAuthn credential registration and verification work.
- MFA enforcement is policy-configurable.

### Task 2.1: Identity Provider Integration (OIDC)

**What:** Implement OIDC-based authentication flow supporting Okta, Azure AD, and Google Workspace as identity providers.

**Design:**

```go
// internal/auth/oidc.go
package auth

import (
    "context"
    "encoding/json"
    "fmt"
    "time"

    "github.com/coreos/go-oidc/v3/oidc"
    "github.com/google/uuid"
    "golang.org/x/oauth2"
)

type OIDCProvider struct {
    TenantID     uuid.UUID
    ProviderID   uuid.UUID
    Name         string
    Provider     *oidc.Provider
    OAuth2Config oauth2.Config
    Verifier     *oidc.IDTokenVerifier
    ClaimMappings map[string]string // Maps IdP claims to internal fields
}

type AuthenticatedIdentity struct {
    ProviderID   uuid.UUID
    ExternalID   string            // "sub" claim
    Email        string
    DisplayName  string
    Groups       []string
    AALLevel     int               // 1, 2, or 3 per NIST SP 800-63B
    MFAMethods   []string
    RawClaims    map[string]interface{}
    AuthTime     time.Time
}

type OIDCManager struct {
    providers map[uuid.UUID]*OIDCProvider // keyed by provider ID
}

func NewOIDCManager() *OIDCManager {
    return &OIDCManager{providers: make(map[uuid.UUID]*OIDCProvider)}
}

func (m *OIDCManager) RegisterProvider(ctx context.Context, cfg IdentityProviderConfig) error {
    provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
    if err != nil {
        return fmt.Errorf("discover OIDC provider %s: %w", cfg.IssuerURL, err)
    }

    verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})

    m.providers[cfg.ProviderID] = &OIDCProvider{
        TenantID:   cfg.TenantID,
        ProviderID: cfg.ProviderID,
        Name:       cfg.Name,
        Provider:   provider,
        Verifier:   verifier,
        OAuth2Config: oauth2.Config{
            ClientID:     cfg.ClientID,
            ClientSecret: cfg.ClientSecret,
            Endpoint:     provider.Endpoint(),
            Scopes:       []string{oidc.ScopeOpenID, "email", "profile", "groups"},
        },
        ClaimMappings: cfg.ClaimMappings,
    }
    return nil
}

func (m *OIDCManager) VerifyToken(ctx context.Context, providerID uuid.UUID, rawIDToken string) (*AuthenticatedIdentity, error) {
    p, ok := m.providers[providerID]
    if !ok {
        return nil, fmt.Errorf("unknown provider %s", providerID)
    }

    idToken, err := p.Verifier.Verify(ctx, rawIDToken)
    if err != nil {
        return nil, fmt.Errorf("verify ID token: %w", err)
    }

    var claims map[string]interface{}
    if err := idToken.Claims(&claims); err != nil {
        return nil, fmt.Errorf("parse claims: %w", err)
    }

    identity := &AuthenticatedIdentity{
        ProviderID: providerID,
        ExternalID: idToken.Subject,
        RawClaims:  claims,
        AuthTime:   idToken.IssuedAt,
    }
    // Map claims using ClaimMappings
    return identity, nil
}
```

```sql
-- migrations/002_identity.up.sql

CREATE TABLE identity_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    provider_type   VARCHAR(50) NOT NULL CHECK (provider_type IN ('oidc', 'saml', 'ldap', 'scim')),
    config          JSONB NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE identity_providers ENABLE ROW LEVEL SECURITY;
CREATE POLICY idp_isolation ON identity_providers USING (tenant_id = current_tenant_id());
CREATE INDEX idx_idp_tenant ON identity_providers(tenant_id);

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    idp_id          UUID NOT NULL REFERENCES identity_providers(id),
    external_id     VARCHAR(255) NOT NULL,
    email           VARCHAR(320),
    display_name    VARCHAR(255),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    idp_claims      JSONB NOT NULL DEFAULT '{}',
    credentials     JSONB NOT NULL DEFAULT '[]',
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
CREATE POLICY user_isolation ON users USING (tenant_id = current_tenant_id());
CREATE UNIQUE INDEX idx_users_tenant_idp_ext ON users(tenant_id, idp_id, external_id);
CREATE INDEX idx_users_email ON users(tenant_id, email);
CREATE INDEX idx_users_claims_groups ON users USING GIN ((idp_claims->'groups'));

CREATE TABLE groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    source          VARCHAR(50) NOT NULL DEFAULT 'local',
    external_id     VARCHAR(255),
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE groups ENABLE ROW LEVEL SECURITY;
CREATE POLICY group_isolation ON groups USING (tenant_id = current_tenant_id());
CREATE UNIQUE INDEX idx_groups_tenant_name ON groups(tenant_id, name);

CREATE TABLE group_members (
    group_id        UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);
```

**Testing:**
- `TestOIDCProviderDiscovery` — Discovers OIDC endpoints from issuer URL.
- `TestOIDCTokenVerification` — Valid ID token returns correct AuthenticatedIdentity.
- `TestOIDCExpiredTokenRejected` — Expired token returns verification error.
- `TestOIDCClaimMapping` — Custom claim mappings correctly extract email, groups, display name.
- `TestOIDCMultipleProviders` — Multiple IdPs can be registered for the same tenant.
- `TestUserCreatedOnFirstLogin` — First authentication creates user record with IdP claims.

### Task 2.2: SAML 2.0 Identity Provider Support

**What:** Implement SAML 2.0 SP-initiated SSO flow for enterprise customers using SAML-based identity providers.

**Design:**

```go
// internal/auth/saml.go
package auth

import (
    "crypto/x509"
    "github.com/crewjam/saml"
    "github.com/crewjam/saml/samlsp"
    "github.com/google/uuid"
)

type SAMLProvider struct {
    TenantID        uuid.UUID
    ProviderID      uuid.UUID
    ServiceProvider saml.ServiceProvider
    Middleware      *samlsp.Middleware
    AttributeMappings map[string]string
}

type SAMLManager struct {
    providers map[uuid.UUID]*SAMLProvider
}

func (m *SAMLManager) RegisterProvider(cfg SAMLProviderConfig) error {
    idpMetadata, err := samlsp.FetchMetadata(
        context.Background(),
        http.DefaultClient,
        cfg.MetadataURL,
    )
    if err != nil {
        return fmt.Errorf("fetch SAML metadata: %w", err)
    }
    // Configure SP with IdP metadata
    return nil
}
```

**Testing:**
- `TestSAMLMetadataFetch` — Correctly parses IdP metadata XML.
- `TestSAMLAssertionValidation` — Valid SAML assertion extracts user identity.
- `TestSAMLExpiredAssertionRejected` — Expired assertions are rejected.
- `TestSAMLAttributeMapping` — Custom attribute mappings extract email and groups from SAML attributes.

### Task 2.3: Device Registration & Posture Assessment

**What:** Implement device registration, posture signal collection, and compliance scoring.

**Design:**

```go
// internal/posture/checker.go
package posture

import (
    "time"
    "github.com/google/uuid"
)

type PostureCheckResult struct {
    OSVersionCompliant  bool `json:"os_version_compliant"`
    DiskEncrypted       bool `json:"disk_encrypted"`
    FirewallEnabled     bool `json:"firewall_enabled"`
    AntivirusActive     bool `json:"antivirus_active"`
    AntivirusUpToDate   bool `json:"antivirus_up_to_date"`
    ScreenLockEnabled   bool `json:"screen_lock_enabled"`
    Jailbroken          bool `json:"jailbroken"`
    CertificateValid    bool `json:"certificate_valid"`
}

type PostureAssessment struct {
    DeviceID          uuid.UUID          `json:"device_id"`
    AssessedAt        time.Time          `json:"assessed_at"`
    ExpiresAt         time.Time          `json:"expires_at"`
    OverallScore      int                `json:"overall_score"`       // 0-100
    OverallCompliant  bool               `json:"overall_compliant"`
    Checks            PostureCheckResult `json:"checks"`
    CustomChecks      map[string]interface{} `json:"custom_checks,omitempty"`
}

type PostureChecker struct {
    minScore          int
    checkTTL          time.Duration
    requiredChecks    []string
}

func (pc *PostureChecker) Assess(signals DeviceSignals) *PostureAssessment {
    score := 100
    checks := PostureCheckResult{}

    // Evaluate each signal against requirements
    if !signals.DiskEncrypted {
        score -= 20
        checks.DiskEncrypted = false
    } else {
        checks.DiskEncrypted = true
    }
    // ... evaluate remaining signals

    return &PostureAssessment{
        DeviceID:         signals.DeviceID,
        AssessedAt:       time.Now(),
        ExpiresAt:        time.Now().Add(pc.checkTTL),
        OverallScore:     score,
        OverallCompliant: score >= pc.minScore,
        Checks:           checks,
    }
}
```

```sql
-- migrations/003_devices.up.sql

CREATE TABLE devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    user_id         UUID REFERENCES users(id),
    device_name     VARCHAR(255),
    serial_number   VARCHAR(255),
    os_type         VARCHAR(50) NOT NULL CHECK (os_type IN (
        'windows', 'macos', 'linux', 'ios', 'android', 'chromeos'
    )),
    os_version      VARCHAR(100),
    hardware_info   JSONB NOT NULL DEFAULT '{}',
    mdm_info        JSONB NOT NULL DEFAULT '{}',
    latest_posture  JSONB NOT NULL DEFAULT '{}',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
CREATE POLICY device_isolation ON devices USING (tenant_id = current_tenant_id());
CREATE INDEX idx_devices_tenant ON devices(tenant_id);
CREATE INDEX idx_devices_user ON devices(user_id);
CREATE INDEX idx_devices_posture ON devices USING GIN (latest_posture);

CREATE TABLE device_posture_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID NOT NULL REFERENCES devices(id),
    assessed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    posture_data    JSONB NOT NULL,
    triggered_by    VARCHAR(50) NOT NULL DEFAULT 'scheduled'
                    CHECK (triggered_by IN ('scheduled', 'session_start', 'mid_session', 'manual', 'mdm_event'))
) PARTITION BY RANGE (assessed_at);

CREATE TABLE device_posture_history_2026_05 PARTITION OF device_posture_history
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE device_posture_history_2026_06 PARTITION OF device_posture_history
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE INDEX idx_posture_history_device ON device_posture_history(device_id, assessed_at DESC);
```

**Testing:**
- `TestDeviceRegistration` — New device is created with hardware info and initial posture.
- `TestPostureAssessmentScoring` — Score correctly computed from individual check results.
- `TestPostureFailsOnMissingEncryption` — Device without disk encryption scores below minimum.
- `TestPostureTTLExpiration` — Expired posture assessment is flagged as non-compliant.
- `TestPostureHistoryAppendOnly` — Assessment history is append-only and partitioned by month.
- `TestCustomPostureChecks` — Custom checks (e.g., EDR status) stored in custom_checks JSONB.

### Task 2.4: WebAuthn/FIDO2 Credential Management

**What:** Implement FIDO2/WebAuthn credential registration and verification for phishing-resistant MFA.

**Design:**

```go
// internal/auth/webauthn.go
package auth

import (
    "github.com/go-webauthn/webauthn/webauthn"
    "github.com/google/uuid"
)

type WebAuthnManager struct {
    webAuthn *webauthn.WebAuthn
}

type WebAuthnUser struct {
    UserID      uuid.UUID
    Email       string
    DisplayName string
    Credentials []webauthn.Credential
}

// Implement webauthn.User interface
func (u *WebAuthnUser) WebAuthnID() []byte            { return u.UserID[:] }
func (u *WebAuthnUser) WebAuthnName() string           { return u.Email }
func (u *WebAuthnUser) WebAuthnDisplayName() string    { return u.DisplayName }
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }

func NewWebAuthnManager(rpDisplayName, rpID, rpOrigin string) (*WebAuthnManager, error) {
    wconfig := &webauthn.Config{
        RPDisplayName: rpDisplayName,
        RPID:          rpID,
        RPOrigins:     []string{rpOrigin},
        AttestationPreference: protocol.PreferDirectAttestation,
        AuthenticatorSelection: protocol.AuthenticatorSelection{
            AuthenticatorAttachment: protocol.CrossPlatform,
            UserVerification:        protocol.VerificationRequired,
            ResidentKey:             protocol.ResidentKeyRequirementPreferred,
        },
    }
    wa, err := webauthn.New(wconfig)
    if err != nil {
        return nil, err
    }
    return &WebAuthnManager{webAuthn: wa}, nil
}

func (m *WebAuthnManager) BeginRegistration(user *WebAuthnUser) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
    return m.webAuthn.BeginRegistration(user)
}

func (m *WebAuthnManager) FinishRegistration(user *WebAuthnUser, sessionData webauthn.SessionData, response *http.Request) (*webauthn.Credential, error) {
    return m.webAuthn.FinishRegistration(user, sessionData, response)
}
```

**Testing:**
- `TestWebAuthnRegistrationBegin` — Returns valid credential creation options.
- `TestWebAuthnRegistrationFinish` — Completes registration and stores credential.
- `TestWebAuthnAuthenticationBegin` — Returns valid assertion options.
- `TestWebAuthnAuthenticationFinish` — Validates assertion and returns AAL2 level.
- `TestWebAuthnMultipleCredentials` — User can register multiple authenticators.

---

## Phase 3: Policy Engine (PDP/PEP)

### Definition of Done
- Access policies can be created, updated, and deleted via API.
- Policy rules support all defined rule types (identity, device, time, geo, risk).
- OPA-based policy evaluation returns allow/deny decisions within 5ms.
- Policy decisions are logged with full evaluation context.
- Compliance templates (SOC 2, HIPAA, FedRAMP, PCI-DSS) can be applied.

### Task 3.1: Access Policy CRUD

**What:** Implement the access policy management API with JSONB rule storage.

**Design:**

```go
// internal/policy/types.go
package policy

import (
    "github.com/google/uuid"
    "time"
)

type RuleType string

const (
    RuleIdentityGroup       RuleType = "identity_group"
    RuleIdentityUser        RuleType = "identity_user"
    RuleDevicePostureMin    RuleType = "device_posture_min_score"
    RuleDeviceOSType        RuleType = "device_os_type"
    RuleDeviceMDMRequired   RuleType = "device_mdm_required"
    RuleTimeWindow          RuleType = "time_window"
    RuleGeoLocation         RuleType = "geo_country"
    RuleIPRange             RuleType = "ip_range"
    RuleMFARequired         RuleType = "mfa_required"
    RuleAALMinimum          RuleType = "aal_minimum"
    RuleApplication         RuleType = "application"
    RuleNetworkSegment      RuleType = "network_segment"
    RuleRiskScoreMax        RuleType = "risk_score_max"
)

type PolicyRule struct {
    Type     RuleType    `json:"type"`
    Operator string      `json:"op"`    // eq, neq, in, not_in, gte, lte, contains
    Value    interface{} `json:"value"`
}

type AccessPolicy struct {
    ID                  uuid.UUID    `json:"id"`
    TenantID            uuid.UUID    `json:"tenant_id"`
    Name                string       `json:"name"`
    Description         string       `json:"description,omitempty"`
    Action              string       `json:"action"`  // allow, deny, require_mfa, require_approval
    Priority            int          `json:"priority"` // Lower = higher priority
    IsActive            bool         `json:"is_active"`
    Rules               []PolicyRule `json:"rules"`
    BoundApplications   []uuid.UUID  `json:"bound_applications"`
    ComplianceFramework string       `json:"compliance_framework,omitempty"`
    Metadata            map[string]interface{} `json:"metadata,omitempty"`
    CreatedAt           time.Time    `json:"created_at"`
    UpdatedAt           time.Time    `json:"updated_at"`
}
```

```sql
-- migrations/004_policies.up.sql

CREATE TABLE access_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    action          VARCHAR(20) NOT NULL CHECK (action IN ('allow', 'deny', 'require_mfa', 'require_approval')),
    priority        INTEGER NOT NULL DEFAULT 100,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    rules           JSONB NOT NULL DEFAULT '[]',
    bound_applications UUID[] NOT NULL DEFAULT '{}',
    compliance_framework VARCHAR(50),
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE access_policies ENABLE ROW LEVEL SECURITY;
CREATE POLICY policy_isolation ON access_policies USING (tenant_id = current_tenant_id());
CREATE INDEX idx_policies_tenant ON access_policies(tenant_id);
CREATE INDEX idx_policies_priority ON access_policies(tenant_id, priority);
CREATE INDEX idx_policies_apps ON access_policies USING GIN (bound_applications);
CREATE INDEX idx_policies_rules ON access_policies USING GIN (rules);

CREATE TABLE compliance_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework       VARCHAR(50) NOT NULL CHECK (framework IN (
        'soc2', 'hipaa', 'fedramp', 'pci_dss_v4', 'gdpr', 'nist_csf_2', 'cisa_ztmm_v2'
    )),
    name            VARCHAR(255) NOT NULL,
    version         VARCHAR(20) NOT NULL,
    template_rules  JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_templates_framework ON compliance_templates(framework, version);
```

**Testing:**
- `TestCreatePolicyWithRules` — Policy created with JSON rules persisted correctly.
- `TestPolicyPriorityOrdering` — Policies retrieved in correct priority order.
- `TestPolicyBindToApplications` — Policy correctly bound to application UUIDs.
- `TestPolicyValidation` — Invalid rule types or operators return 400.
- `TestPolicyDuplicateNameRejected` — Duplicate policy name within tenant returns 409.
- `TestComplianceTemplateApplication` — Applying HIPAA template creates policy with required rules.

### Task 3.2: OPA-Based Policy Evaluation Engine

**What:** Implement the Policy Decision Point (PDP) using embedded OPA for real-time access decisions.

**Design:**

```go
// internal/policy/engine.go
package policy

import (
    "context"
    "fmt"
    "time"

    "github.com/google/uuid"
    "github.com/open-policy-agent/opa/v1/rego"
)

type AccessRequest struct {
    UserID        uuid.UUID              `json:"user_id"`
    DeviceID      uuid.UUID              `json:"device_id"`
    ApplicationID uuid.UUID              `json:"application_id"`
    IPAddress     string                 `json:"ip_address"`
    GeoCountry    string                 `json:"geo_country"`
    GeoCity       string                 `json:"geo_city"`
    AALLevel      int                    `json:"aal_level"`
    PostureScore  int                    `json:"posture_score"`
    RiskScore     int                    `json:"risk_score"`
    Groups        []string               `json:"groups"`
    DeviceOS      string                 `json:"device_os"`
    MDMEnrolled   bool                   `json:"mdm_enrolled"`
    Timestamp     time.Time              `json:"timestamp"`
    Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

type AccessDecision struct {
    Decision        string    `json:"decision"`    // allow, deny, challenge, quarantine
    MatchedPolicyID uuid.UUID `json:"matched_policy_id,omitempty"`
    RiskScore       int       `json:"risk_score"`
    PostureScore    int       `json:"posture_score"`
    AALLevel        int       `json:"aal_level"`
    EvaluationMs    int       `json:"evaluation_ms"`
    RuleEvaluations []RuleEvaluation `json:"rule_evaluations"`
}

type RuleEvaluation struct {
    Type     RuleType `json:"type"`
    Result   bool     `json:"result"`
    Actual   interface{} `json:"actual,omitempty"`
    Required interface{} `json:"required,omitempty"`
}

type PolicyEngine struct {
    compiler *rego.PreparedEvalQuery
    store    PolicyStore
}

func NewPolicyEngine(store PolicyStore) (*PolicyEngine, error) {
    // Compile base Rego module
    query, err := rego.New(
        rego.Query("data.ztna.access.decision"),
        rego.Module("access.rego", accessRegoModule),
    ).PrepareForEval(context.Background())
    if err != nil {
        return nil, fmt.Errorf("compile rego: %w", err)
    }
    return &PolicyEngine{compiler: &query, store: store}, nil
}

func (e *PolicyEngine) Evaluate(ctx context.Context, req AccessRequest) (*AccessDecision, error) {
    start := time.Now()

    // Fetch applicable policies for the application
    policies, err := e.store.GetActivePoliciesForApp(ctx, req.ApplicationID)
    if err != nil {
        return nil, fmt.Errorf("fetch policies: %w", err)
    }

    // Build OPA input document
    input := map[string]interface{}{
        "request":  req,
        "policies": policies,
    }

    results, err := e.compiler.Eval(ctx, rego.EvalInput(input))
    if err != nil {
        return nil, fmt.Errorf("evaluate policy: %w", err)
    }

    decision := parseDecision(results)
    decision.EvaluationMs = int(time.Since(start).Milliseconds())
    return decision, nil
}
```

```rego
# internal/policy/rego/access.rego
package ztna.access

import rego.v1

default decision := {"result": "deny", "reason": "no matching policy"}

decision := result if {
    some policy in input.policies
    policy.is_active
    all_rules_match(policy.rules, input.request)
    result := {
        "result": policy.action,
        "matched_policy_id": policy.id,
        "rule_evaluations": [eval |
            some rule in policy.rules
            eval := evaluate_rule(rule, input.request)
        ],
    }
}

all_rules_match(rules, request) if {
    every rule in rules {
        evaluate_rule(rule, request).result == true
    }
}

evaluate_rule(rule, request) := {"type": rule.type, "result": true, "actual": request.groups} if {
    rule.type == "identity_group"
    rule.op == "in"
    some group in request.groups
    group == rule.value
}

evaluate_rule(rule, request) := {"type": rule.type, "result": result, "actual": request.posture_score, "required": rule.value} if {
    rule.type == "device_posture_min_score"
    rule.op == "gte"
    result := request.posture_score >= rule.value
}

evaluate_rule(rule, request) := {"type": rule.type, "result": result, "actual": request.aal_level, "required": rule.value} if {
    rule.type == "aal_minimum"
    rule.op == "gte"
    result := request.aal_level >= rule.value
}

evaluate_rule(rule, request) := {"type": rule.type, "result": true, "actual": request.geo_country} if {
    rule.type == "geo_country"
    rule.op == "in"
    request.geo_country in rule.value
}
```

**Testing:**
- `TestPolicyEvaluationAllowsMatchingRequest` — Request matching all rules returns "allow".
- `TestPolicyEvaluationDeniesNonMatchingRequest` — Request failing any rule returns "deny".
- `TestPolicyPriorityResolution` — Higher-priority deny overrides lower-priority allow.
- `TestPolicyEvaluationPerformanceUnder5ms` — 100 policies evaluated in under 5ms.
- `TestPostureScoreRuleEvaluation` — Device with score 95 passes min_score 80 rule.
- `TestGeoLocationRuleEvaluation` — Request from US passes geo_country "in" ["US","CA","GB"] rule.
- `TestTimeWindowRuleEvaluation` — Request at 10:00 Mon passes 09:00-18:00/Mon-Fri rule.
- `TestMFARequiredRuleEvaluation` — Request with AAL1 fails aal_minimum 2 rule.
- `TestDefaultDenyNoMatchingPolicy` — Request with no applicable policies returns deny.

### Task 3.3: Policy Decision Logging

**What:** Log every policy evaluation decision with full context for audit and compliance.

**Design:**

```sql
-- migrations/005_policy_decisions.up.sql

CREATE TABLE policy_decisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    decision_time   TIMESTAMPTZ NOT NULL DEFAULT now(),
    decision        VARCHAR(20) NOT NULL CHECK (decision IN ('allow', 'deny', 'challenge', 'quarantine')),
    evaluation      JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (decision_time);

CREATE TABLE policy_decisions_2026_05 PARTITION OF policy_decisions
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE policy_decisions_2026_06 PARTITION OF policy_decisions
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE INDEX idx_pd_tenant_time ON policy_decisions(tenant_id, decision_time DESC);
CREATE INDEX idx_pd_decision ON policy_decisions(decision, decision_time DESC);
CREATE INDEX idx_pd_evaluation ON policy_decisions USING GIN (evaluation);
```

**Testing:**
- `TestDecisionLoggedOnAllow` — Allow decision creates policy_decisions record.
- `TestDecisionLoggedOnDeny` — Deny decision includes evaluated_policies and failure reasons.
- `TestDecisionEvaluationContainsRuleDetails` — Each rule evaluation result stored in JSONB.
- `TestDecisionQueryByTimeRange` — Decisions efficiently queryable by time range via partition.
- `TestDecisionQueryByUser` — Decisions queryable by user_id within evaluation JSONB.

---

## Phase 4: Connector & Data Plane

### Definition of Done
- Connector agent binary can be deployed and registered with the control plane.
- Outbound-only gRPC/mTLS connection from connector to control plane operational.
- Connector heartbeat and health monitoring functional.
- Application registration and connector-to-application routing working.
- Traffic tunnelling via connector to private applications functional.

### Task 4.1: Application Registration

**What:** Implement application definition and management for web, SSH, RDP, database, and Kubernetes targets.

**Design:**

```go
// internal/models/application.go
package models

import (
    "github.com/google/uuid"
    "time"
)

type ApplicationType string

const (
    AppTypeWeb        ApplicationType = "web"
    AppTypeSSH        ApplicationType = "ssh"
    AppTypeRDP        ApplicationType = "rdp"
    AppTypeDatabase   ApplicationType = "database"
    AppTypeKubernetes ApplicationType = "kubernetes"
    AppTypeAPI        ApplicationType = "api"
    AppTypeTCP        ApplicationType = "tcp"
    AppTypeUDP        ApplicationType = "udp"
)

type Application struct {
    ID         uuid.UUID              `json:"id"`
    TenantID   uuid.UUID              `json:"tenant_id"`
    Name       string                 `json:"name"`
    AppType    ApplicationType        `json:"app_type"`
    Connection map[string]interface{} `json:"connection"`
    Tags       []string               `json:"tags"`
    IsActive   bool                   `json:"is_active"`
    CreatedAt  time.Time              `json:"created_at"`
    UpdatedAt  time.Time              `json:"updated_at"`
}

type WebConnection struct {
    InternalHost string `json:"internal_host"`
    InternalPort int    `json:"internal_port"`
    Protocol     string `json:"protocol"`
    ExternalDomain string `json:"external_domain,omitempty"`
    TLSVerify    bool   `json:"tls_verify"`
    HealthCheckPath string `json:"health_check_path,omitempty"`
}

type SSHConnection struct {
    InternalHost        string   `json:"internal_host"`
    InternalPort        int      `json:"internal_port"`
    SessionRecording    bool     `json:"session_recording"`
    AllowedCommands     []string `json:"allowed_commands,omitempty"`
    MaxSessionDuration  int      `json:"max_session_duration_minutes"`
}

type KubernetesConnection struct {
    ClusterName          string   `json:"cluster_name"`
    APIServer            string   `json:"api_server"`
    NamespaceRestrictions []string `json:"namespace_restrictions,omitempty"`
    AllowedResources     []string `json:"allowed_resources,omitempty"`
    AllowedVerbs         []string `json:"allowed_verbs,omitempty"`
}
```

```sql
-- migrations/006_applications.up.sql

CREATE TABLE applications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    app_type        VARCHAR(50) NOT NULL CHECK (app_type IN (
        'web', 'ssh', 'rdp', 'database', 'kubernetes', 'api', 'tcp', 'udp'
    )),
    connection      JSONB NOT NULL,
    tags            JSONB NOT NULL DEFAULT '[]',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE applications ENABLE ROW LEVEL SECURITY;
CREATE POLICY app_isolation ON applications USING (tenant_id = current_tenant_id());
CREATE INDEX idx_apps_tenant ON applications(tenant_id);
CREATE UNIQUE INDEX idx_apps_tenant_name ON applications(tenant_id, name);
CREATE INDEX idx_apps_tags ON applications USING GIN (tags);
```

**Testing:**
- `TestCreateWebApplication` — Web app created with connection JSONB containing host, port, protocol.
- `TestCreateSSHApplication` — SSH app created with session recording and allowed commands.
- `TestCreateKubernetesApplication` — K8s app created with namespace restrictions.
- `TestApplicationTags` — Tags queryable via GIN index.
- `TestApplicationTypeValidation` — Invalid app_type returns 400.

### Task 4.2: Connector Registration & Heartbeat

**What:** Implement the connector agent lifecycle: registration with one-time token, gRPC/mTLS connection, and periodic heartbeat.

**Design:**

```go
// internal/connector/registry.go
package connector

import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "time"
    "github.com/google/uuid"
)

type ConnectorStatus string

const (
    StatusPending        ConnectorStatus = "pending"
    StatusOnline         ConnectorStatus = "online"
    StatusOffline        ConnectorStatus = "offline"
    StatusDegraded       ConnectorStatus = "degraded"
    StatusDecommissioned ConnectorStatus = "decommissioned"
)

type ConnectorRegistration struct {
    TenantID uuid.UUID `json:"tenant_id"`
    Name     string    `json:"name"`
    Token    string    `json:"token"` // One-time registration token
}

type ConnectorInfo struct {
    ID            uuid.UUID              `json:"id"`
    TenantID      uuid.UUID              `json:"tenant_id"`
    Name          string                 `json:"name"`
    Status        ConnectorStatus        `json:"status"`
    Config        map[string]interface{} `json:"config"`
    LinkedAppIDs  []uuid.UUID            `json:"linked_app_ids"`
    LastHeartbeat *time.Time             `json:"last_heartbeat"`
    CreatedAt     time.Time              `json:"created_at"`
}

type Registry struct {
    store ConnectorStore
    pki   *PKIManager
}

func (r *Registry) Register(ctx context.Context, reg ConnectorRegistration) (*ConnectorInfo, *x509.Certificate, error) {
    // Validate one-time token
    tokenHash := sha256.Sum256([]byte(reg.Token))
    tokenHex := hex.EncodeToString(tokenHash[:])

    // Issue mTLS certificate for connector identity
    cert, err := r.pki.IssueConnectorCertificate(reg.TenantID, reg.Name)
    if err != nil {
        return nil, nil, fmt.Errorf("issue certificate: %w", err)
    }

    // Create connector record
    connector := &ConnectorInfo{
        ID:       uuid.New(),
        TenantID: reg.TenantID,
        Name:     reg.Name,
        Status:   StatusPending,
    }
    // Persist and return
    return connector, cert, nil
}
```

```go
// internal/connector/heartbeat.go
package connector

import (
    "context"
    "log/slog"
    "time"
    "github.com/google/uuid"
)

type HeartbeatPayload struct {
    ConnectorID    uuid.UUID `json:"connector_id"`
    Version        string    `json:"version"`
    UptimeSeconds  int64     `json:"uptime_seconds"`
    ActiveSessions int       `json:"active_sessions"`
    CPUPercent     float64   `json:"cpu_percent"`
    MemoryPercent  float64   `json:"memory_percent"`
}

type HeartbeatMonitor struct {
    store    ConnectorStore
    timeout  time.Duration // Mark offline after this duration without heartbeat
}

func (m *HeartbeatMonitor) ProcessHeartbeat(ctx context.Context, hb HeartbeatPayload) error {
    return m.store.UpdateHeartbeat(ctx, hb.ConnectorID, time.Now(), hb)
}

func (m *HeartbeatMonitor) CheckStaleConnectors(ctx context.Context) error {
    threshold := time.Now().Add(-m.timeout)
    stale, err := m.store.FindConnectorsWithHeartbeatBefore(ctx, threshold)
    if err != nil {
        return err
    }
    for _, c := range stale {
        slog.Warn("connector heartbeat timeout", "connector_id", c.ID, "last_heartbeat", c.LastHeartbeat)
        m.store.UpdateStatus(ctx, c.ID, StatusOffline)
    }
    return nil
}
```

```sql
-- migrations/007_connectors.up.sql

CREATE TABLE connectors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    token_hash      VARCHAR(128) NOT NULL,
    status          VARCHAR(30) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'online', 'offline', 'degraded', 'decommissioned')),
    config          JSONB NOT NULL DEFAULT '{}',
    linked_app_ids  UUID[] NOT NULL DEFAULT '{}',
    last_heartbeat  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE connectors ENABLE ROW LEVEL SECURITY;
CREATE POLICY connector_isolation ON connectors USING (tenant_id = current_tenant_id());
CREATE INDEX idx_connectors_tenant ON connectors(tenant_id);
CREATE INDEX idx_connectors_status ON connectors(tenant_id, status);
```

**Testing:**
- `TestConnectorRegistrationWithToken` — Valid token registers connector and returns mTLS certificate.
- `TestConnectorRegistrationInvalidToken` — Invalid token returns 401.
- `TestConnectorHeartbeat` — Heartbeat updates last_heartbeat and status to online.
- `TestConnectorTimeoutMarksOffline` — Connector without heartbeat for 90s marked offline.
- `TestConnectorDecommission` — Decommissioned connector cannot send heartbeats.
- `TestConnectorLinkToApplications` — Connector linked to application IDs correctly.

### Task 4.3: gRPC Transport & Tunnel

**What:** Implement the gRPC bidirectional streaming transport between connector and control plane for session data relay.

**Design:**

```protobuf
// proto/connector/v1/connector.proto
syntax = "proto3";
package ztna.connector.v1;

service ConnectorService {
    // Bidirectional stream for connector-control plane communication
    rpc Connect(stream ConnectorMessage) returns (stream ControlPlaneMessage);

    // Heartbeat
    rpc Heartbeat(HeartbeatRequest) returns (HeartbeatResponse);
}

message ConnectorMessage {
    oneof payload {
        SessionData session_data = 1;
        HealthReport health_report = 2;
        ApplicationStatus app_status = 3;
    }
}

message ControlPlaneMessage {
    oneof payload {
        SessionEstablish session_establish = 1;
        SessionTerminate session_terminate = 2;
        PolicyUpdate policy_update = 3;
        ConfigUpdate config_update = 4;
    }
}

message SessionEstablish {
    string session_id = 1;
    string application_id = 2;
    string user_id = 3;
    string target_host = 4;
    int32 target_port = 5;
    string protocol = 6;
}

message SessionTerminate {
    string session_id = 1;
    string reason = 2;
}

message SessionData {
    string session_id = 1;
    bytes data = 2;
}

message HeartbeatRequest {
    string connector_id = 1;
    string version = 2;
    int64 uptime_seconds = 3;
    int32 active_sessions = 4;
    double cpu_percent = 5;
    double memory_percent = 6;
}

message HeartbeatResponse {
    bool acknowledged = 1;
    int32 heartbeat_interval_seconds = 2;
}
```

**Testing:**
- `TestGRPCConnectionWithMTLS` — Connector connects via mTLS with valid certificate.
- `TestGRPCConnectionRejectsInvalidCert` — Connection rejected with invalid certificate.
- `TestBidirectionalStreaming` — Messages flow in both directions.
- `TestSessionEstablishRoute` — Control plane sends session establish to correct connector.
- `TestSessionTerminateRelayed` — Session terminate propagated to connector.
- `TestReconnectionAfterDisconnect` — Connector auto-reconnects after network interruption.

---

## Phase 5: Session Management & Continuous Verification

### Definition of Done
- Access sessions created upon successful policy evaluation.
- Session tokens (JWT) issued with configurable TTL.
- Mid-session continuous verification runs at configurable intervals.
- Sessions terminated on policy violation, timeout, or admin action.
- Risk score updated in real-time during active sessions.

### Task 5.1: Session Lifecycle Management

**What:** Implement session creation, token issuance, and termination.

**Design:**

```go
// internal/session/manager.go
package session

import (
    "context"
    "time"
    "github.com/google/uuid"
    "github.com/golang-jwt/jwt/v5"
)

type SessionStatus string

const (
    SessionActive      SessionStatus = "active"
    SessionTerminated  SessionStatus = "terminated"
    SessionExpired     SessionStatus = "expired"
    SessionQuarantined SessionStatus = "quarantined"
    SessionEscalated   SessionStatus = "escalated"
)

type Session struct {
    ID              uuid.UUID              `json:"id"`
    TenantID        uuid.UUID              `json:"tenant_id"`
    UserID          uuid.UUID              `json:"user_id"`
    DeviceID        uuid.UUID              `json:"device_id"`
    ApplicationID   uuid.UUID              `json:"application_id"`
    ConnectorID     *uuid.UUID             `json:"connector_id,omitempty"`
    PolicyID        uuid.UUID              `json:"policy_id"`
    Status          SessionStatus          `json:"status"`
    RiskScore       int                    `json:"risk_score"`
    Context         map[string]interface{} `json:"context"`
    StartedAt       time.Time              `json:"started_at"`
    LastVerifiedAt  time.Time              `json:"last_verified_at"`
    EndedAt         *time.Time             `json:"ended_at,omitempty"`
    TerminationReason string              `json:"termination_reason,omitempty"`
}

type SessionManager struct {
    store         SessionStore
    policyEngine  *PolicyEngine
    tokenIssuer   *TokenIssuer
    verifyInterval time.Duration
}

func (m *SessionManager) CreateSession(ctx context.Context, req AccessRequest, decision AccessDecision) (*Session, string, error) {
    session := &Session{
        ID:            uuid.New(),
        TenantID:      req.TenantID,
        UserID:        req.UserID,
        DeviceID:      req.DeviceID,
        ApplicationID: req.ApplicationID,
        PolicyID:      decision.MatchedPolicyID,
        Status:        SessionActive,
        RiskScore:     decision.RiskScore,
        Context: map[string]interface{}{
            "ip_address":           req.IPAddress,
            "geo_country":          req.GeoCountry,
            "geo_city":             req.GeoCity,
            "aal_level":            req.AALLevel,
            "posture_score_at_start": decision.PostureScore,
            "matched_rules":        decision.RuleEvaluations,
        },
        StartedAt:      time.Now(),
        LastVerifiedAt: time.Now(),
    }

    if err := m.store.Create(ctx, session); err != nil {
        return nil, "", err
    }

    token, err := m.tokenIssuer.IssueSessionToken(session)
    if err != nil {
        return nil, "", err
    }

    return session, token, nil
}

func (m *SessionManager) TerminateSession(ctx context.Context, sessionID uuid.UUID, reason string) error {
    now := time.Now()
    return m.store.Update(ctx, sessionID, map[string]interface{}{
        "status":             SessionTerminated,
        "ended_at":           now,
        "termination_reason": reason,
    })
}
```

```sql
-- migrations/008_sessions.up.sql

CREATE TABLE access_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    user_id         UUID NOT NULL REFERENCES users(id),
    device_id       UUID NOT NULL REFERENCES devices(id),
    application_id  UUID NOT NULL REFERENCES applications(id),
    connector_id    UUID REFERENCES connectors(id),
    policy_id       UUID NOT NULL REFERENCES access_policies(id),
    status          VARCHAR(30) NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active', 'terminated', 'expired', 'quarantined', 'escalated')),
    risk_score      SMALLINT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    context         JSONB NOT NULL DEFAULT '{}',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    termination_reason VARCHAR(50),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE access_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY session_isolation ON access_sessions USING (tenant_id = current_tenant_id());
CREATE INDEX idx_sessions_tenant_active ON access_sessions(tenant_id, status) WHERE status = 'active';
CREATE INDEX idx_sessions_user ON access_sessions(user_id, started_at DESC);
CREATE INDEX idx_sessions_app ON access_sessions(application_id, started_at DESC);
```

**Testing:**
- `TestCreateSessionOnAllow` — Allowed access request creates active session.
- `TestSessionTokenIssuedOnCreation` — JWT issued with session ID, user, and TTL.
- `TestTerminateSession` — Session status changes to terminated with reason.
- `TestExpiredSessionRejected` — Expired session token returns 401.
- `TestAdminKillSession` — Admin can force-terminate any active session.
- `TestConcurrentSessionLimit` — Tenant-configurable max concurrent sessions enforced.

### Task 5.2: Continuous Verification Engine

**What:** Implement mid-session re-evaluation of trust at configurable intervals (ZTNA 2.0 pattern).

**Design:**

```go
// internal/session/verifier.go
package session

import (
    "context"
    "log/slog"
    "time"
    "github.com/google/uuid"
)

type VerificationResult string

const (
    VerifyPass       VerificationResult = "pass"
    VerifyWarn       VerificationResult = "warn"
    VerifyFail       VerificationResult = "fail"
    VerifyQuarantine VerificationResult = "quarantine"
)

type Verification struct {
    ID                uuid.UUID          `json:"id"`
    SessionID         uuid.UUID          `json:"session_id"`
    VerifiedAt        time.Time          `json:"verified_at"`
    Result            VerificationResult `json:"result"`
    RiskScore         int                `json:"risk_score"`
    PostureScore      int                `json:"posture_score"`
    IPChanged         bool               `json:"ip_changed"`
    GeoChanged        bool               `json:"geo_changed"`
    ActionTaken       string             `json:"action_taken"`
    VerificationData  map[string]interface{} `json:"verification_data"`
}

type ContinuousVerifier struct {
    sessionStore  SessionStore
    postureChecker *PostureChecker
    policyEngine  *PolicyEngine
    interval      time.Duration
}

func (v *ContinuousVerifier) VerifySession(ctx context.Context, session *Session) (*Verification, error) {
    // 1. Re-assess device posture
    posture, err := v.postureChecker.GetLatestAssessment(ctx, session.DeviceID)
    if err != nil {
        return nil, err
    }

    // 2. Check for IP/geo changes
    currentIP := getCurrentIP(ctx, session.ID)
    ipChanged := currentIP != session.Context["ip_address"]
    geoChanged := false // Compare geo lookup

    // 3. Re-evaluate policy
    req := buildAccessRequest(session, posture, currentIP)
    decision, err := v.policyEngine.Evaluate(ctx, req)

    // 4. Determine verification result
    var result VerificationResult
    var action string
    switch {
    case decision.Decision == "deny":
        result = VerifyFail
        action = "session_terminated"
    case decision.RiskScore > 70:
        result = VerifyQuarantine
        action = "session_quarantined"
    case decision.RiskScore > 50:
        result = VerifyWarn
        action = "risk_elevated"
    default:
        result = VerifyPass
        action = "none"
    }

    verification := &Verification{
        ID:           uuid.New(),
        SessionID:    session.ID,
        VerifiedAt:   time.Now(),
        Result:       result,
        RiskScore:    decision.RiskScore,
        PostureScore: posture.OverallScore,
        IPChanged:    ipChanged,
        GeoChanged:   geoChanged,
        ActionTaken:  action,
    }

    // 5. Take action
    switch result {
    case VerifyFail:
        v.sessionStore.TerminateSession(ctx, session.ID, "continuous_verification_failed")
    case VerifyQuarantine:
        v.sessionStore.QuarantineSession(ctx, session.ID)
    }

    return verification, nil
}
```

```sql
-- migrations/009_session_verifications.up.sql

CREATE TABLE session_verifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES access_sessions(id),
    verified_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    result          VARCHAR(20) NOT NULL CHECK (result IN ('pass', 'warn', 'fail', 'quarantine')),
    verification_data JSONB NOT NULL,
    action_taken    VARCHAR(30)
);

CREATE INDEX idx_verifications_session ON session_verifications(session_id, verified_at DESC);
```

**Testing:**
- `TestContinuousVerificationPass` — Session passing all checks returns "pass".
- `TestVerificationFailTerminatesSession` — Failed verification terminates the session.
- `TestVerificationQuarantinesHighRisk` — Risk score >70 quarantines the session.
- `TestIPChangeDetected` — IP address change flagged in verification result.
- `TestGeoChangeDetected` — Geographic location change detected and logged.
- `TestVerificationInterval` — Verifications run at configured interval (15-60 minutes).
- `TestPostureExpirationTriggersRecheck` — Expired posture forces new assessment.

---

## Phase 6: Session Recording & Audit

### Definition of Done
- SSH and RDP sessions are recorded and stored in S3-compatible storage.
- OCSF-aligned audit events logged for all security-relevant operations.
- Audit log queryable by time range, actor, resource, and event type.
- Audit events exportable to SIEM platforms.

### Task 6.1: Session Recording

**What:** Implement SSH and RDP session recording with encrypted storage.

**Design:**

```go
// internal/session/recorder.go
package session

import (
    "context"
    "io"
    "time"
    "github.com/google/uuid"
)

type RecordingType string

const (
    RecordingSSH          RecordingType = "ssh"
    RecordingRDP          RecordingType = "rdp"
    RecordingDatabaseQuery RecordingType = "database_query"
)

type Recording struct {
    ID               uuid.UUID              `json:"id"`
    SessionID        uuid.UUID              `json:"session_id"`
    RecordingType    RecordingType           `json:"recording_type"`
    StorageURI       string                 `json:"storage_uri"`
    Metadata         map[string]interface{} `json:"metadata"`
    CreatedAt        time.Time              `json:"created_at"`
}

type Recorder struct {
    storage     ObjectStorage
    encryption  EncryptionManager
}

func (r *Recorder) StartRecording(ctx context.Context, sessionID uuid.UUID, recType RecordingType) (*RecordingWriter, error) {
    recording := &Recording{
        ID:            uuid.New(),
        SessionID:     sessionID,
        RecordingType: recType,
        StorageURI:    fmt.Sprintf("s3://%s/recordings/%s/%s", r.bucket, sessionID, uuid.New()),
        Metadata: map[string]interface{}{
            "started_at":        time.Now(),
            "encryption_key_ref": r.encryption.CurrentKeyRef(),
        },
    }
    writer, err := r.storage.NewWriter(ctx, recording.StorageURI)
    if err != nil {
        return nil, err
    }
    encryptedWriter := r.encryption.WrapWriter(writer)
    return &RecordingWriter{recording: recording, writer: encryptedWriter}, nil
}
```

**Testing:**
- `TestSSHSessionRecording` — SSH session data is captured and stored encrypted.
- `TestRecordingPlayback` — Recorded session can be decrypted and replayed.
- `TestRecordingStorageURI` — Storage URI follows expected S3 path convention.
- `TestRecordingMetadata` — Metadata includes duration, size, and encryption key ref.
- `TestRecordingCleanupOnSessionEnd` — Recording finalized and metadata updated on session end.

### Task 6.2: OCSF-Aligned Audit Logging

**What:** Implement comprehensive audit logging using OCSF event classification for SIEM compatibility.

**Design:**

```go
// internal/audit/logger.go
package audit

import (
    "context"
    "time"
    "github.com/google/uuid"
)

type OCSFClassUID int

const (
    OCSFAuthentication     OCSFClassUID = 300201
    OCSFAuthorization      OCSFClassUID = 300301
    OCSFSessionActivity    OCSFClassUID = 300401
    OCSFPolicyChange       OCSFClassUID = 500101
    OCSFDeviceInventory    OCSFClassUID = 500201
    OCSFAccountChange      OCSFClassUID = 300101
)

type Severity int

const (
    SeverityInfo     Severity = 1
    SeverityLow      Severity = 2
    SeverityMedium   Severity = 3
    SeverityHigh     Severity = 4
    SeverityCritical Severity = 5
)

type AuditEvent struct {
    ID            uuid.UUID              `json:"id"`
    TenantID      uuid.UUID              `json:"tenant_id"`
    EventTime     time.Time              `json:"event_time"`
    EventType     string                 `json:"event_type"`
    Severity      Severity               `json:"severity"`
    OCSFClassUID  OCSFClassUID           `json:"ocsf_class_uid"`
    Actor         map[string]interface{} `json:"actor"`
    Resource      map[string]interface{} `json:"resource"`
    EventData     map[string]interface{} `json:"event_data"`
    Outcome       string                 `json:"outcome"`
}

type AuditLogger struct {
    store AuditStore
}

func (l *AuditLogger) Log(ctx context.Context, event AuditEvent) error {
    if event.ID == uuid.Nil {
        event.ID = uuid.New()
    }
    if event.EventTime.IsZero() {
        event.EventTime = time.Now()
    }
    return l.store.Insert(ctx, event)
}

func (l *AuditLogger) LogSessionStarted(ctx context.Context, session *Session, user *User) error {
    return l.Log(ctx, AuditEvent{
        TenantID:     session.TenantID,
        EventType:    "session.started",
        Severity:     SeverityInfo,
        OCSFClassUID: OCSFSessionActivity,
        Actor:        map[string]interface{}{"type": "user", "id": user.ID, "email": user.Email},
        Resource:     map[string]interface{}{"type": "application", "id": session.ApplicationID},
        EventData:    map[string]interface{}{"session_id": session.ID, "risk_score": session.RiskScore},
        Outcome:      "success",
    })
}
```

```sql
-- migrations/010_audit.up.sql

CREATE TABLE audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type      VARCHAR(100) NOT NULL,
    severity        SMALLINT NOT NULL DEFAULT 1,
    ocsf_class_uid  INTEGER,
    actor           JSONB NOT NULL,
    resource        JSONB NOT NULL,
    event_data      JSONB NOT NULL DEFAULT '{}',
    outcome         VARCHAR(20) NOT NULL CHECK (outcome IN ('success', 'failure', 'error', 'unknown'))
) PARTITION BY RANGE (event_time);

CREATE TABLE audit_events_2026_05 PARTITION OF audit_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_events_2026_06 PARTITION OF audit_events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE INDEX idx_audit_tenant_time ON audit_events(tenant_id, event_time DESC);
CREATE INDEX idx_audit_type ON audit_events(event_type, event_time DESC);
CREATE INDEX idx_audit_actor ON audit_events USING GIN (actor);
CREATE INDEX idx_audit_resource ON audit_events USING GIN (resource);
```

**Testing:**
- `TestAuditLogSessionStarted` — Session start creates audit event with OCSF classification.
- `TestAuditLogPolicyChanged` — Policy changes logged with before/after state.
- `TestAuditLogQueryByTimeRange` — Efficient time-range queries via partition pruning.
- `TestAuditLogQueryByActor` — Query by actor.id within JSONB returns correct events.
- `TestAuditLogOCSFExport` — Events exportable in OCSF-compatible JSON format.
- `TestAuditLogPartitionCreation` — New monthly partitions created automatically.

---

## Phase 7: Multi-Cloud & Network Topology

### Definition of Done
- Network segments defined with CIDR ranges and ltree hierarchy.
- Connectors associated with cloud regions and VPCs.
- SPIFFE workload identities for service-to-service zero trust.
- Graph edge layer operational for relationship queries.

### Task 7.1: Network Segment Management

**What:** Implement network segment definitions with hierarchical relationships using PostgreSQL ltree.

**Design:**

```sql
-- migrations/011_network.up.sql

CREATE TABLE network_segments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    cidr            CIDR NOT NULL,
    environment     VARCHAR(50) CHECK (environment IN ('production', 'staging', 'development', 'dmz')),
    hierarchy_path  LTREE,
    cloud_info      JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE network_segments ENABLE ROW LEVEL SECURITY;
CREATE POLICY segment_isolation ON network_segments USING (tenant_id = current_tenant_id());
CREATE INDEX idx_segments_tenant ON network_segments(tenant_id);
CREATE INDEX idx_segments_hierarchy ON network_segments USING GIST (hierarchy_path);
CREATE INDEX idx_segments_cidr ON network_segments USING GIST (cidr inet_ops);

CREATE TABLE org_units (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    hierarchy_path  LTREE NOT NULL,
    parent_id       UUID REFERENCES org_units(id),
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE org_units ENABLE ROW LEVEL SECURITY;
CREATE POLICY ou_isolation ON org_units USING (tenant_id = current_tenant_id());
CREATE INDEX idx_ou_hierarchy ON org_units USING GIST (hierarchy_path);

CREATE TABLE workload_identities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    spiffe_id       TEXT NOT NULL,
    application_id  UUID REFERENCES applications(id),
    attestation     JSONB NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE workload_identities ENABLE ROW LEVEL SECURITY;
CREATE POLICY workload_isolation ON workload_identities USING (tenant_id = current_tenant_id());
CREATE UNIQUE INDEX idx_workload_spiffe ON workload_identities(tenant_id, spiffe_id);
```

**Testing:**
- `TestNetworkSegmentCreation` — Segment created with CIDR and ltree path.
- `TestSegmentHierarchyQuery` — Descendant query with `<@` operator returns child segments.
- `TestCIDRContainmentQuery` — IP address containment check against segment CIDR ranges.
- `TestOrgUnitHierarchy` — Org unit hierarchy traversable via ltree.
- `TestWorkloadIdentitySPIFFE` — Workload identity stores SPIFFE ID with attestation JSONB.

### Task 7.2: Graph Edge Layer

**What:** Implement the graph relationship layer for trust chain analysis, blast radius, and conflict-of-interest detection.

**Design:**

```sql
-- migrations/012_graph.up.sql

CREATE TABLE graph_nodes (
    node_id         UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    node_type       VARCHAR(50) NOT NULL CHECK (node_type IN (
        'user', 'group', 'device', 'application', 'connector',
        'network_segment', 'policy', 'org_unit', 'role',
        'workload_identity', 'idp', 'service_account', 'tenant'
    )),
    label           VARCHAR(255) NOT NULL,
    hierarchy_path  LTREE,
    properties      JSONB NOT NULL DEFAULT '{}',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_gn_tenant_type ON graph_nodes(tenant_id, node_type);
CREATE INDEX idx_gn_hierarchy ON graph_nodes USING GIST (hierarchy_path);
CREATE INDEX idx_gn_properties ON graph_nodes USING GIN (properties);

CREATE TABLE graph_edges (
    edge_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    source_node_id  UUID NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
    target_node_id  UUID NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
    edge_type       VARCHAR(50) NOT NULL CHECK (edge_type IN (
        'member_of', 'has_role', 'authenticated_by', 'owns',
        'can_access', 'protected_by', 'enforced_at', 'serves', 'connects_to',
        'belongs_to', 'child_of', 'reports_to',
        'subnet_of', 'hosts', 'peers_with',
        'compliant_with', 'audited_by', 'trusts', 'attested_by', 'delegates_to'
    )),
    weight          REAL NOT NULL DEFAULT 1.0,
    properties      JSONB NOT NULL DEFAULT '{}',
    valid_from      TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ge_source ON graph_edges(source_node_id, edge_type) WHERE valid_until IS NULL;
CREATE INDEX idx_ge_target ON graph_edges(target_node_id, edge_type) WHERE valid_until IS NULL;
CREATE INDEX idx_ge_tenant_type ON graph_edges(tenant_id, edge_type);
CREATE UNIQUE INDEX idx_ge_unique_active ON graph_edges(source_node_id, target_node_id, edge_type)
    WHERE valid_until IS NULL;
```

```go
// internal/graph/traversal.go
package graph

import (
    "context"
    "github.com/google/uuid"
)

type BlastRadiusResult struct {
    NodeID   uuid.UUID `json:"node_id"`
    NodeType string    `json:"node_type"`
    Label    string    `json:"label"`
    Hops     int       `json:"hops"`
    Path     []uuid.UUID `json:"path"`
}

type GraphTraverser struct {
    store GraphStore
}

func (t *GraphTraverser) BlastRadius(ctx context.Context, startNodeID uuid.UUID, maxHops int) ([]BlastRadiusResult, error) {
    // Recursive CTE-based BFS from start node through active edges
    query := `
    WITH RECURSIVE blast_radius AS (
        SELECT node_id, node_type, label, 0 AS hops, ARRAY[node_id] AS path
        FROM graph_nodes WHERE node_id = $1
        UNION ALL
        SELECT gn.node_id, gn.node_type, gn.label, br.hops + 1, br.path || gn.node_id
        FROM blast_radius br
        JOIN graph_edges e ON (e.source_node_id = br.node_id OR e.target_node_id = br.node_id)
        JOIN graph_nodes gn ON gn.node_id = CASE
            WHEN e.source_node_id = br.node_id THEN e.target_node_id
            ELSE e.source_node_id
        END
        WHERE e.valid_until IS NULL
          AND br.hops < $2
          AND NOT (gn.node_id = ANY(br.path))
    )
    SELECT node_id, node_type, label, hops, path
    FROM blast_radius
    WHERE node_type IN ('application', 'user', 'network_segment')
    ORDER BY hops ASC, node_type`

    // Execute and scan results
    return nil, nil
}

func (t *GraphTraverser) AccessPaths(ctx context.Context, userID, appID uuid.UUID) ([][]uuid.UUID, error) {
    // Find all paths from user to application through groups, roles, and policies
    return nil, nil
}
```

**Testing:**
- `TestBlastRadiusFromDevice` — Compromised device identifies reachable apps and users within N hops.
- `TestAccessPathVerification` — Finds all paths from user to application.
- `TestTemporalGraphQuery` — Graph reconstructed at a historical timestamp via valid_from/valid_until.
- `TestConflictOfInterest` — Detects user with both admin and auditor roles on same application.
- `TestGraphEdgeSyncOnGroupMembership` — Adding user to group creates member_of edge.
- `TestGraphEdgeExpiration` — Removing user from group expires edge (valid_until set).

---

## Phase 8: AI Anomaly Detection & Risk Scoring

### Definition of Done
- Behavioral baselines computed per user from historical access patterns.
- Real-time anomaly detection identifies impossible travel, unusual times, and new devices.
- Adaptive risk scoring adjusts session risk in real-time.
- Detected anomalies trigger configurable remediation actions.

### Task 8.1: Behavioral Baselining

**What:** Compute per-user behavioral baselines from historical access data for anomaly detection.

**Design:**

```go
// internal/ai/anomaly/baseline.go
package anomaly

import (
    "context"
    "math"
    "time"
    "github.com/google/uuid"
)

type BaselineType string

const (
    BaselineLoginTime     BaselineType = "login_time"
    BaselineGeoPattern    BaselineType = "geo_pattern"
    BaselineAppUsage      BaselineType = "app_usage"
    BaselineSessionDuration BaselineType = "session_duration"
    BaselineDataVolume    BaselineType = "data_volume"
)

type BehavioralBaseline struct {
    UserID       uuid.UUID     `json:"user_id"`
    Type         BaselineType  `json:"type"`
    Statistics   BaselineStats `json:"statistics"`
    Confidence   float64       `json:"confidence"`    // 0.0-1.0
    SampleCount  int           `json:"sample_count"`
    ComputedAt   time.Time     `json:"computed_at"`
    ValidUntil   time.Time     `json:"valid_until"`
}

type BaselineStats struct {
    Mean             float64            `json:"mean"`
    StdDev           float64            `json:"std_dev"`
    Percentile95     float64            `json:"p95"`
    Percentile99     float64            `json:"p99"`
    HourDistribution [24]float64        `json:"hour_distribution"`  // Probability per hour
    DayDistribution  [7]float64         `json:"day_distribution"`   // Probability per weekday
    GeoFrequency     map[string]float64 `json:"geo_frequency"`      // Country -> frequency
    AppFrequency     map[string]float64 `json:"app_frequency"`      // App ID -> frequency
}

type BaselineComputer struct {
    sessionStore SessionStore
    lookback     time.Duration // e.g., 90 days
    minSamples   int           // Minimum sessions for confident baseline
}

func (bc *BaselineComputer) ComputeForUser(ctx context.Context, userID uuid.UUID) ([]BehavioralBaseline, error) {
    sessions, err := bc.sessionStore.GetUserSessionHistory(ctx, userID, bc.lookback)
    if err != nil {
        return nil, err
    }

    if len(sessions) < bc.minSamples {
        return nil, nil // Not enough data for confident baseline
    }

    baselines := []BehavioralBaseline{
        bc.computeLoginTimeBaseline(userID, sessions),
        bc.computeGeoBaseline(userID, sessions),
        bc.computeAppUsageBaseline(userID, sessions),
    }
    return baselines, nil
}

func (bc *BaselineComputer) computeLoginTimeBaseline(userID uuid.UUID, sessions []Session) BehavioralBaseline {
    hourDist := [24]float64{}
    for _, s := range sessions {
        hour := s.StartedAt.Hour()
        hourDist[hour]++
    }
    // Normalize to probabilities
    total := float64(len(sessions))
    for i := range hourDist {
        hourDist[i] /= total
    }

    return BehavioralBaseline{
        UserID:      userID,
        Type:        BaselineLoginTime,
        Statistics:  BaselineStats{HourDistribution: hourDist},
        Confidence:  math.Min(float64(len(sessions))/100.0, 1.0),
        SampleCount: len(sessions),
        ComputedAt:  time.Now(),
        ValidUntil:  time.Now().Add(7 * 24 * time.Hour),
    }
}
```

**Testing:**
- `TestBaselineComputesHourDistribution` — Login time baseline correctly distributes across 24 hours.
- `TestBaselineGeoFrequency` — Geo pattern tracks country access frequencies.
- `TestBaselineMinSamples` — Returns nil for users with fewer than minimum samples.
- `TestBaselineConfidenceScaling` — Confidence increases with sample count.
- `TestBaselineExpiration` — Baselines have configurable TTL and are recomputed periodically.

### Task 8.2: Real-Time Anomaly Detection

**What:** Detect access anomalies in real-time by comparing current behavior against baselines.

**Design:**

```go
// internal/ai/anomaly/detector.go
package anomaly

import (
    "context"
    "math"
    "time"
    "github.com/google/uuid"
)

type AnomalyType string

const (
    AnomalyImpossibleTravel   AnomalyType = "impossible_travel"
    AnomalyUnusualTime        AnomalyType = "unusual_time"
    AnomalyNewDevice          AnomalyType = "new_device"
    AnomalyRiskScoreSpike     AnomalyType = "risk_score_spike"
    AnomalyUnusualApp         AnomalyType = "unusual_app"
    AnomalyDataExfiltration   AnomalyType = "data_exfiltration"
    AnomalyBruteForce         AnomalyType = "brute_force"
    AnomalyCredentialStuffing AnomalyType = "credential_stuffing"
)

type DetectedAnomaly struct {
    ID              uuid.UUID              `json:"id"`
    TenantID        uuid.UUID              `json:"tenant_id"`
    UserID          *uuid.UUID             `json:"user_id,omitempty"`
    DeviceID        *uuid.UUID             `json:"device_id,omitempty"`
    SessionID       *uuid.UUID             `json:"session_id,omitempty"`
    DetectionType   AnomalyType            `json:"detection_type"`
    Severity        int                    `json:"severity"`     // 1-5
    Confidence      float64                `json:"confidence"`   // 0.0-1.0
    Details         map[string]interface{} `json:"details"`
    Remediation     string                 `json:"remediation,omitempty"`
    DetectedAt      time.Time              `json:"detected_at"`
}

type AnomalyDetector struct {
    baselineStore BaselineStore
    sessionStore  SessionStore
    geoService    GeoIPService
}

func (d *AnomalyDetector) CheckImpossibleTravel(ctx context.Context, userID uuid.UUID, currentGeo GeoLocation, currentTime time.Time) (*DetectedAnomaly, error) {
    lastSession, err := d.sessionStore.GetLastSession(ctx, userID)
    if err != nil || lastSession == nil {
        return nil, nil
    }

    lastGeo := lastSession.GeoLocation()
    timeDelta := currentTime.Sub(lastSession.StartedAt)
    distance := haversineDistance(lastGeo.Lat, lastGeo.Lon, currentGeo.Lat, currentGeo.Lon)

    // Max reasonable travel speed: 1000 km/h (fast commercial flight)
    maxDistance := 1000.0 * timeDelta.Hours()

    if distance > maxDistance {
        return &DetectedAnomaly{
            ID:            uuid.New(),
            UserID:        &userID,
            DetectionType: AnomalyImpossibleTravel,
            Severity:      4,
            Confidence:    math.Min(distance/maxDistance, 1.0),
            Details: map[string]interface{}{
                "previous_location": lastGeo,
                "current_location":  currentGeo,
                "time_gap_minutes":  timeDelta.Minutes(),
                "distance_km":       distance,
            },
            DetectedAt: time.Now(),
        }, nil
    }
    return nil, nil
}

func (d *AnomalyDetector) CheckUnusualTime(ctx context.Context, userID uuid.UUID, loginTime time.Time) (*DetectedAnomaly, error) {
    baseline, err := d.baselineStore.Get(ctx, userID, BaselineLoginTime)
    if err != nil || baseline == nil {
        return nil, nil
    }

    hour := loginTime.Hour()
    probability := baseline.Statistics.HourDistribution[hour]

    if probability < 0.01 { // Less than 1% of historical logins at this hour
        return &DetectedAnomaly{
            ID:            uuid.New(),
            UserID:        &userID,
            DetectionType: AnomalyUnusualTime,
            Severity:      2,
            Confidence:    1.0 - probability,
            Details: map[string]interface{}{
                "login_hour":           hour,
                "historical_probability": probability,
            },
            DetectedAt: time.Now(),
        }, nil
    }
    return nil, nil
}
```

**Testing:**
- `TestImpossibleTravelDetected` — Login from NYC followed by Moscow 45min later flagged.
- `TestImpossibleTravelNotFlaggedForReasonableTravel` — NYC to Boston 4h later not flagged.
- `TestUnusualTimeDetected` — 3am login for user who never logs in after midnight flagged.
- `TestUnusualTimeNotFlaggedForNormalHours` — 10am login for daytime user not flagged.
- `TestNewDeviceDetected` — Login from unregistered device flagged.
- `TestBruteForceDetected` — 10 failed logins in 5 minutes flagged.
- `TestAnomalyConfidenceScaling` — Confidence increases with deviation magnitude.

### Task 8.3: Adaptive Risk Scoring

**What:** Compute and update session risk scores in real-time based on multiple signal sources.

**Design:**

```go
// internal/ai/anomaly/risk_scorer.go
package anomaly

import (
    "context"
    "github.com/google/uuid"
)

type RiskSignal struct {
    Source     string  `json:"source"`      // posture, anomaly, geo, time, behavior
    Score     int      `json:"score"`       // 0-100 contribution
    Weight    float64  `json:"weight"`      // Signal weight
    Reason    string   `json:"reason"`
}

type RiskAssessment struct {
    SessionID   uuid.UUID     `json:"session_id"`
    TotalScore  int           `json:"total_score"`   // 0-100 composite
    Signals     []RiskSignal  `json:"signals"`
    Action      string        `json:"recommended_action"` // none, elevate, mfa_prompt, quarantine, terminate
}

type RiskScorer struct {
    anomalyDetector  *AnomalyDetector
    postureChecker   *PostureChecker
    weights          map[string]float64
}

func NewRiskScorer() *RiskScorer {
    return &RiskScorer{
        weights: map[string]float64{
            "posture":  0.30,
            "anomaly":  0.25,
            "geo":      0.15,
            "time":     0.10,
            "behavior": 0.20,
        },
    }
}

func (rs *RiskScorer) Score(ctx context.Context, session *Session) (*RiskAssessment, error) {
    signals := []RiskSignal{}

    // Posture signal
    postureSignal := rs.scorePosture(ctx, session.DeviceID)
    signals = append(signals, postureSignal)

    // Anomaly signals
    anomalySignals := rs.scoreAnomalies(ctx, session)
    signals = append(signals, anomalySignals...)

    // Compute weighted total
    totalScore := 0.0
    for _, s := range signals {
        totalScore += float64(s.Score) * s.Weight
    }
    normalizedScore := int(min(totalScore, 100))

    action := "none"
    switch {
    case normalizedScore > 80:
        action = "terminate"
    case normalizedScore > 60:
        action = "quarantine"
    case normalizedScore > 40:
        action = "mfa_prompt"
    case normalizedScore > 20:
        action = "elevate"
    }

    return &RiskAssessment{
        SessionID:  session.ID,
        TotalScore: normalizedScore,
        Signals:    signals,
        Action:     action,
    }, nil
}
```

**Testing:**
- `TestRiskScoreComposite` — Multiple signals produce weighted composite score.
- `TestHighRiskRecommendsTermination` — Score >80 recommends session termination.
- `TestMediumRiskRecommendsMFA` — Score 40-60 recommends MFA prompt.
- `TestLowRiskNoAction` — Score <20 recommends no action.
- `TestPostureWeightContribution` — Non-compliant device posture increases total risk.
- `TestAnomalyWeightContribution` — Impossible travel anomaly significantly raises risk.

---

## Phase 9: Frontend Dashboard

### Definition of Done
- Security dashboard showing active sessions, risk summary, and connector status.
- Policy management UI with rule builder and compliance template application.
- Device inventory with posture status.
- Audit log viewer with filtering and export.
- Application and connector management pages.

### Task 9.1: Dashboard Layout & Authentication

**What:** Set up the Next.js application with authentication, layout, and navigation.

**Design:**

```typescript
// frontend/src/lib/api-client.ts
interface ZTNAClient {
    tenants: {
        get(): Promise<Tenant>;
        updateSettings(settings: Record<string, unknown>): Promise<Tenant>;
    };
    sessions: {
        list(params?: SessionListParams): Promise<PaginatedResponse<Session>>;
        get(id: string): Promise<Session>;
        terminate(id: string, reason: string): Promise<void>;
    };
    policies: {
        list(): Promise<Policy[]>;
        create(policy: PolicyCreate): Promise<Policy>;
        update(id: string, policy: PolicyUpdate): Promise<Policy>;
        delete(id: string): Promise<void>;
    };
    devices: {
        list(params?: DeviceListParams): Promise<PaginatedResponse<Device>>;
        get(id: string): Promise<Device>;
    };
    applications: {
        list(): Promise<Application[]>;
        create(app: ApplicationCreate): Promise<Application>;
    };
    connectors: {
        list(): Promise<Connector[]>;
        register(req: ConnectorRegister): Promise<ConnectorRegistrationResult>;
    };
    audit: {
        list(params: AuditListParams): Promise<PaginatedResponse<AuditEvent>>;
        export(params: AuditExportParams): Promise<Blob>;
    };
    dashboard: {
        summary(): Promise<DashboardSummary>;
    };
}

// frontend/src/types/api.ts
interface DashboardSummary {
    active_sessions: number;
    high_risk_sessions: number;
    non_compliant_devices: number;
    failed_access_last_hour: number;
    anomalies_last_24h: number;
    connectors_online: number;
    connectors_offline: number;
    policy_decisions_today: {
        allow: number;
        deny: number;
        challenge: number;
    };
}

interface Session {
    id: string;
    user: { id: string; email: string; display_name: string };
    device: { id: string; device_name: string; os_type: string };
    application: { id: string; name: string; app_type: string };
    status: 'active' | 'terminated' | 'expired' | 'quarantined' | 'escalated';
    risk_score: number;
    started_at: string;
    last_verified_at: string;
}

interface Policy {
    id: string;
    name: string;
    description?: string;
    action: 'allow' | 'deny' | 'require_mfa' | 'require_approval';
    priority: number;
    is_active: boolean;
    rules: PolicyRule[];
    bound_applications: string[];
    compliance_framework?: string;
}

interface PolicyRule {
    type: string;
    op: string;
    value: unknown;
}
```

**Testing:**
- `TestDashboardRendersSessionCounts` — Dashboard shows active and high-risk session counts.
- `TestDashboardRendersConnectorStatus` — Online/offline connector counts displayed.
- `TestNavigationBetweenPages` — Sidebar navigation links work correctly.
- `TestAuthenticationRedirect` — Unauthenticated users redirected to login.
- `TestRoleBasedUIElements` — Viewer role cannot see policy edit buttons.

### Task 9.2: Policy Management UI

**What:** Build the policy creation and editing interface with visual rule builder.

**Design:**

```typescript
// frontend/src/components/policies/PolicyRuleBuilder.tsx
interface PolicyRuleBuilderProps {
    rules: PolicyRule[];
    onChange: (rules: PolicyRule[]) => void;
    availableGroups: string[];
    availableApplications: Application[];
}

type RuleTypeConfig = {
    label: string;
    operators: { value: string; label: string }[];
    valueType: 'text' | 'number' | 'select' | 'multi-select' | 'time-window' | 'boolean';
    options?: { value: string; label: string }[];
};

const RULE_TYPES: Record<string, RuleTypeConfig> = {
    identity_group: {
        label: 'User Group',
        operators: [{ value: 'in', label: 'is member of' }, { value: 'not_in', label: 'is not member of' }],
        valueType: 'multi-select',
    },
    device_posture_min_score: {
        label: 'Device Posture Score',
        operators: [{ value: 'gte', label: 'at least' }],
        valueType: 'number',
    },
    geo_country: {
        label: 'Country',
        operators: [{ value: 'in', label: 'is in' }, { value: 'not_in', label: 'is not in' }],
        valueType: 'multi-select',
    },
    time_window: {
        label: 'Time Window',
        operators: [{ value: 'in', label: 'during' }],
        valueType: 'time-window',
    },
    mfa_required: {
        label: 'MFA Required',
        operators: [{ value: 'eq', label: 'equals' }],
        valueType: 'boolean',
    },
    aal_minimum: {
        label: 'Authentication Assurance Level',
        operators: [{ value: 'gte', label: 'at least' }],
        valueType: 'select',
        options: [
            { value: '1', label: 'AAL1 - Single factor' },
            { value: '2', label: 'AAL2 - Multi-factor' },
            { value: '3', label: 'AAL3 - Hardware-bound' },
        ],
    },
    risk_score_max: {
        label: 'Maximum Risk Score',
        operators: [{ value: 'lte', label: 'at most' }],
        valueType: 'number',
    },
};
```

**Testing:**
- `TestPolicyRuleBuilderAddsRule` — Clicking "Add Rule" adds a new rule row.
- `TestPolicyRuleBuilderDeletesRule` — Deleting a rule removes it from the list.
- `TestPolicyRuleBuilderOperatorOptions` — Operators change based on selected rule type.
- `TestPolicyCreationSubmit` — Form submission creates policy via API.
- `TestComplianceTemplateApply` — Applying HIPAA template pre-fills required rules.
- `TestPolicyPriorityDragReorder` — Drag-and-drop reorders policy priorities.

### Task 9.3: Session & Audit Views

**What:** Build the active session monitoring view and audit log viewer.

**Design:**

```typescript
// frontend/src/types/api.ts (additional types)
interface SessionListParams {
    status?: 'active' | 'terminated' | 'quarantined';
    user_id?: string;
    application_id?: string;
    risk_score_min?: number;
    page?: number;
    per_page?: number;
}

interface AuditListParams {
    start_time: string;
    end_time: string;
    event_type?: string;
    actor_id?: string;
    resource_type?: string;
    severity_min?: number;
    page?: number;
    per_page?: number;
}
```

**Testing:**
- `TestSessionListFiltering` — Sessions filterable by status, user, and application.
- `TestSessionKillButton` — Admin can terminate a session from the UI.
- `TestSessionRiskScoreColor` — Risk scores displayed with color coding (green/yellow/red).
- `TestAuditLogTimeRangeFilter` — Audit events filterable by time range.
- `TestAuditLogExport` — Export button downloads events as JSON or CSV.
- `TestAuditLogSeverityFilter` — Events filterable by severity level.

---

## Phase 10: AI Policy Generation & Natural Language Authoring

### Definition of Done
- AI auto-generates least-privilege policy suggestions from observed access patterns.
- Natural language policy authoring translates prose to enforcement rules.
- AI suggestions require human review (pending/accepted/rejected workflow).
- Policy suggestion confidence scores and rationale are displayed.

### Task 10.1: AI Policy Suggestion Engine

**What:** Analyze historical access patterns to generate policy recommendations.

**Design:**

```go
// internal/ai/llm/policy_generator.go
package llm

import (
    "context"
    "time"
    "github.com/google/uuid"
)

type PolicySuggestion struct {
    ID              uuid.UUID              `json:"id"`
    TenantID        uuid.UUID              `json:"tenant_id"`
    SuggestedName   string                 `json:"suggested_name"`
    SuggestedAction string                 `json:"suggested_action"`
    SuggestedRules  []PolicyRule           `json:"suggested_rules"`
    Rationale       string                 `json:"rationale"`
    Confidence      float64                `json:"confidence"`
    BasedOnSessions int                    `json:"based_on_sessions"`
    Status          string                 `json:"status"` // pending, accepted, rejected, modified
    ReviewedBy      *uuid.UUID             `json:"reviewed_by,omitempty"`
    CreatedAt       time.Time              `json:"created_at"`
    ReviewedAt      *time.Time             `json:"reviewed_at,omitempty"`
}

type PolicyGenerator struct {
    llmClient    LLMClient
    sessionStore SessionStore
    policyStore  PolicyStore
}

func (pg *PolicyGenerator) GenerateSuggestions(ctx context.Context, tenantID uuid.UUID) ([]PolicySuggestion, error) {
    // 1. Fetch recent access patterns grouped by user groups and applications
    patterns, err := pg.sessionStore.GetAccessPatterns(ctx, tenantID, 30*24*time.Hour)
    if err != nil {
        return nil, err
    }

    // 2. Identify clusters of similar access behavior
    clusters := clusterAccessPatterns(patterns)

    // 3. For each cluster, generate a policy suggestion
    suggestions := []PolicySuggestion{}
    for _, cluster := range clusters {
        suggestion, err := pg.generateForCluster(ctx, tenantID, cluster)
        if err != nil {
            continue
        }
        suggestions = append(suggestions, *suggestion)
    }

    return suggestions, nil
}
```

```sql
-- migrations/013_ai_insights.up.sql

CREATE TABLE ai_insights (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    insight_type    VARCHAR(50) NOT NULL CHECK (insight_type IN (
        'policy_suggestion', 'anomaly', 'behavioral_baseline', 'risk_forecast'
    )),
    status          VARCHAR(30) NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'accepted', 'rejected', 'modified', 'expired')),
    insight_data    JSONB NOT NULL,
    reviewed_by     UUID REFERENCES users(id),
    reviewed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE ai_insights ENABLE ROW LEVEL SECURITY;
CREATE POLICY insight_isolation ON ai_insights USING (tenant_id = current_tenant_id());
CREATE INDEX idx_insights_tenant ON ai_insights(tenant_id, insight_type, status, created_at DESC);
```

**Testing:**
- `TestPolicySuggestionFromAccessPatterns` — Groups with consistent access patterns generate policy suggestions.
- `TestSuggestionConfidenceScaling` — Confidence increases with more supporting sessions.
- `TestSuggestionRationale` — Rationale explains why the policy was suggested.
- `TestSuggestionAcceptCreatePolicy` — Accepting a suggestion creates an active policy.
- `TestSuggestionRejectWorkflow` — Rejected suggestions are marked and not re-suggested.
- `TestHumanInTheLoopRequired` — Suggestions always start in "pending" status.

### Task 10.2: Natural Language Policy Authoring

**What:** Translate natural language descriptions into ZTNA policy rules using LLM.

**Design:**

```go
// internal/ai/llm/nl_policy.go
package llm

import (
    "context"
    "encoding/json"
    "fmt"
)

type NLPolicyRequest struct {
    NaturalLanguage string `json:"natural_language"`
    // Context for better translation
    AvailableGroups       []string `json:"available_groups"`
    AvailableApplications []string `json:"available_applications"`
    TenantTimezone        string   `json:"tenant_timezone"`
}

type NLPolicyResult struct {
    ParsedRules     []PolicyRule `json:"parsed_rules"`
    SuggestedName   string       `json:"suggested_name"`
    SuggestedAction string       `json:"suggested_action"`
    Explanation     string       `json:"explanation"`
    Confidence      float64      `json:"confidence"`
    Warnings        []string     `json:"warnings,omitempty"`
}

type NLPolicyTranslator struct {
    llmClient LLMClient
}

func (t *NLPolicyTranslator) Translate(ctx context.Context, req NLPolicyRequest) (*NLPolicyResult, error) {
    prompt := fmt.Sprintf(`Translate this access policy description into structured rules.

Natural language: "%s"

Available groups: %v
Available applications: %v
Timezone: %s

Return JSON with: parsed_rules (array of {type, op, value}), suggested_name, suggested_action (allow/deny), explanation, confidence (0-1), and any warnings.

Valid rule types: identity_group, identity_user, device_posture_min_score, device_os_type,
device_mdm_required, time_window, geo_country, ip_range, mfa_required, aal_minimum,
risk_score_max.`,
        req.NaturalLanguage,
        req.AvailableGroups,
        req.AvailableApplications,
        req.TenantTimezone,
    )

    response, err := t.llmClient.Complete(ctx, prompt)
    if err != nil {
        return nil, err
    }

    var result NLPolicyResult
    if err := json.Unmarshal([]byte(response), &result); err != nil {
        return nil, fmt.Errorf("parse LLM response: %w", err)
    }
    return &result, nil
}
```

**Testing:**
- `TestNLTranslateContractorBusinessHours` — "Allow contractors to access billing 9-5 weekdays" produces time_window and identity_group rules.
- `TestNLTranslateGeoRestriction` — "Deny access from outside US and Canada" produces geo_country deny rule.
- `TestNLTranslateMFARequirement` — "Require MFA for production database access" produces mfa_required rule.
- `TestNLTranslateAmbiguousInput` — Ambiguous input returns warnings and lower confidence.
- `TestNLTranslateUnrecognizedGroup` — References to non-existent groups generate warnings.
- `TestNLPreservesOriginalText` — Original natural language stored in policy metadata.

---

## Phase 11: Compliance Templates & Reporting

### Definition of Done
- Pre-built compliance templates for SOC 2, HIPAA, FedRAMP, PCI-DSS, and GDPR.
- Compliance posture dashboard showing coverage per framework.
- Audit evidence export in framework-specific formats.
- Gap analysis identifying policies that don't meet framework requirements.

### Task 11.1: Compliance Template Engine

**What:** Implement compliance templates that define required policy rules per regulatory framework.

**Design:**

```go
// internal/policy/compliance.go
package policy

import "github.com/google/uuid"

type ComplianceFramework string

const (
    FrameworkSOC2      ComplianceFramework = "soc2"
    FrameworkHIPAA     ComplianceFramework = "hipaa"
    FrameworkFedRAMP   ComplianceFramework = "fedramp"
    FrameworkPCIDSS    ComplianceFramework = "pci_dss_v4"
    FrameworkGDPR      ComplianceFramework = "gdpr"
    FrameworkNISTCSF   ComplianceFramework = "nist_csf_2"
    FrameworkCISAZTMM  ComplianceFramework = "cisa_ztmm_v2"
)

type ComplianceTemplate struct {
    ID              uuid.UUID              `json:"id"`
    Framework       ComplianceFramework    `json:"framework"`
    Name            string                 `json:"name"`
    Version         string                 `json:"version"`
    RequiredRules   []TemplateRule         `json:"required_rules"`
    RecommendedRules []TemplateRule        `json:"recommended_rules"`
    SessionSettings TemplateSessionSettings `json:"session_settings"`
}

type TemplateRule struct {
    Type      string `json:"type"`
    Operator  string `json:"op"`
    Value     interface{} `json:"value"`
    Rationale string `json:"rationale"`
    Control   string `json:"control"` // e.g., "HIPAA 164.312(d)" or "PCI-DSS 1.3.1"
}

type TemplateSessionSettings struct {
    MaxDurationHours          int  `json:"max_duration_hours"`
    VerificationIntervalMin   int  `json:"verification_interval_minutes"`
    SessionRecordingRequired  bool `json:"session_recording"`
}

type ComplianceGapAnalysis struct {
    Framework     ComplianceFramework `json:"framework"`
    TotalControls int                `json:"total_controls"`
    MetControls   int                `json:"met_controls"`
    GapControls   []GapControl       `json:"gap_controls"`
    Score         float64            `json:"score"` // 0-100
}

type GapControl struct {
    Control     string `json:"control"`
    Requirement string `json:"requirement"`
    Status      string `json:"status"` // met, partial, missing
    Remediation string `json:"remediation"`
}
```

**Testing:**
- `TestHIPAATemplateRequiresMFA` — HIPAA template includes mfa_required rule with 164.312(d) rationale.
- `TestFedRAMPTemplateRequiresAAL2` — FedRAMP template requires AAL level 2 minimum.
- `TestGapAnalysisIdentifiesMissing` — Gap analysis flags policies missing required rules.
- `TestGapAnalysisScoring` — Compliance score reflects percentage of controls met.
- `TestTemplateApplication` — Applying template creates policy with all required rules.
- `TestMultiFrameworkOverlap` — Policy satisfying HIPAA also partially satisfies SOC 2.

### Task 11.2: Compliance Reporting & Evidence Export

**What:** Generate compliance reports and export audit evidence in format suitable for auditors.

**Design:**

```go
// internal/audit/export.go
package audit

import (
    "context"
    "time"
)

type ComplianceReport struct {
    Framework      string    `json:"framework"`
    GeneratedAt    time.Time `json:"generated_at"`
    Period         DateRange `json:"period"`
    OverallScore   float64   `json:"overall_score"`
    ControlResults []ControlResult `json:"control_results"`
    Evidence       []EvidenceItem  `json:"evidence"`
}

type ControlResult struct {
    ControlID   string `json:"control_id"`
    Description string `json:"description"`
    Status      string `json:"status"`
    Evidence    []string `json:"evidence_refs"`
}

type EvidenceItem struct {
    ID          string    `json:"id"`
    Type        string    `json:"type"` // policy_decision, audit_event, session_recording
    Description string    `json:"description"`
    Timestamp   time.Time `json:"timestamp"`
    Data        interface{} `json:"data"`
}

type AuditExporter struct {
    auditStore AuditStore
    sessionStore SessionStore
}

func (e *AuditExporter) ExportOCSF(ctx context.Context, tenantID uuid.UUID, period DateRange) ([]byte, error) {
    // Export audit events in OCSF JSON format for SIEM import
    return nil, nil
}

func (e *AuditExporter) GenerateComplianceReport(ctx context.Context, tenantID uuid.UUID, framework ComplianceFramework, period DateRange) (*ComplianceReport, error) {
    // Generate framework-specific compliance report with evidence
    return nil, nil
}
```

**Testing:**
- `TestComplianceReportGeneration` — Report generated with control results and evidence items.
- `TestOCSFExportFormat` — Export produces valid OCSF-structured JSON.
- `TestEvidenceLinksToAuditEvents` — Evidence items reference actual audit event IDs.
- `TestReportPeriodFiltering` — Report covers only the specified date range.
- `TestReportExportPDF` — Report exportable as formatted PDF for auditors.

---

## Phase 12: Production Hardening & Deployment

### Definition of Done
- Rate limiting, input validation, and security headers on all API endpoints.
- Kubernetes Helm chart with horizontal pod autoscaling.
- Health checks, readiness probes, and graceful shutdown.
- Prometheus metrics and structured logging.
- Penetration testing checklist completed.
- End-to-end integration test suite passing.

### Task 12.1: API Security Hardening

**What:** Implement rate limiting, input validation, CORS, and security headers per OWASP API Security Top 10.

**Design:**

```go
// internal/api/middleware/ratelimit.go
package middleware

import (
    "net/http"
    "time"

    "github.com/go-chi/httprate"
)

func RateLimit(requestsPerMinute int) func(http.Handler) http.Handler {
    return httprate.LimitByIP(requestsPerMinute, time.Minute)
}

func RateLimitByTenant(requestsPerMinute int) func(http.Handler) http.Handler {
    return httprate.Limit(
        requestsPerMinute,
        time.Minute,
        httprate.WithKeyFuncs(func(r *http.Request) (string, error) {
            tenantID := r.Context().Value("tenant_id")
            if tenantID == nil {
                return r.RemoteAddr, nil
            }
            return tenantID.(string), nil
        }),
    )
}

// internal/api/middleware/security.go
func SecurityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("X-XSS-Protection", "0")
        w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        w.Header().Set("Content-Security-Policy", "default-src 'self'")
        w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
        w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        next.ServeHTTP(w, r)
    })
}
```

**Testing:**
- `TestRateLimitExceeded` — Exceeding rate limit returns 429 with Retry-After header.
- `TestSecurityHeadersPresent` — All OWASP-recommended headers present on every response.
- `TestCORSRejectsUnknownOrigin` — CORS blocks requests from non-whitelisted origins.
- `TestInputValidationRejectsOversize` — Request body >1MB rejected.
- `TestSQLInjectionPrevented` — SQL injection attempts in query params return 400.
- `TestXSSPrevented` — Script tags in request body sanitized or rejected.

### Task 12.2: Kubernetes Deployment & Helm Chart

**What:** Create production Kubernetes deployment with Helm chart, HPA, and observability.

**Design:**

```yaml
# deploy/helm/ztna/values.yaml
replicaCount: 3

image:
  repository: ghcr.io/your-org/ztna-control-plane
  tag: latest
  pullPolicy: IfNotPresent

controlPlane:
  httpPort: 8080
  grpcPort: 9090
  resources:
    requests:
      cpu: 500m
      memory: 512Mi
    limits:
      cpu: 2000m
      memory: 2Gi

autoscaling:
  enabled: true
  minReplicas: 3
  maxReplicas: 20
  targetCPUUtilizationPercentage: 70
  targetMemoryUtilizationPercentage: 80

postgresql:
  enabled: true
  auth:
    postgresPassword: ""
    database: ztna
  primary:
    persistence:
      size: 50Gi

redis:
  enabled: true
  architecture: standalone
  auth:
    enabled: true

ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
  tls:
    - secretName: ztna-tls
      hosts:
        - ztna.example.com

monitoring:
  prometheus:
    enabled: true
    serviceMonitor: true
  grafana:
    dashboards: true
```

**Testing:**
- `TestHelmTemplateRenders` — `helm template` produces valid Kubernetes manifests.
- `TestHelmValuesOverride` — Custom values correctly override defaults.
- `TestHealthProbeConfiguration` — Liveness and readiness probes configured correctly.
- `TestHPAScaling` — HPA scales up under CPU pressure.
- `TestGracefulShutdown` — Pod shutdown drains connections within terminationGracePeriod.
- `TestPDBConfiguration` — PodDisruptionBudget prevents total service loss during rollout.

### Task 12.3: End-to-End Integration Tests

**What:** Full workflow integration tests covering the critical path from authentication through session management.

**Design:**

```go
// tests/e2e/access_flow_test.go
package e2e

func TestCompleteAccessFlow(t *testing.T) {
    // 1. Create tenant
    // 2. Register identity provider
    // 3. Register device with posture
    // 4. Register application
    // 5. Register connector
    // 6. Create access policy
    // 7. Authenticate user
    // 8. Request access -> policy evaluation -> session created
    // 9. Continuous verification passes
    // 10. Terminate session
    // 11. Verify audit log contains all events
}
```

**Testing:**
- `TestCompleteAccessFlow` — End-to-end access from auth to session termination.
- `TestDenyFlowProducesAuditTrail` — Denied access creates full audit trail.
- `TestContinuousVerificationFlowQuarantines` — Posture change mid-session quarantines.
- `TestConnectorFailoverFlow` — Application accessible via backup connector.
- `TestComplianceReportAfterActivity` — Compliance report includes evidence from test activity.
- `TestMultiTenantIsolation` — Tenant A operations invisible to Tenant B.

---

## Definition of Done — Project-Level Checklist

- [ ] All 12 phases implemented and passing tests
- [ ] OpenAPI 3.1 specification generated and published
- [ ] PostgreSQL migrations apply cleanly from empty database
- [ ] Docker Compose local development stack boots in under 60 seconds
- [ ] Helm chart deploys to Kubernetes successfully
- [ ] NIST SP 800-207 PDP/PEP architecture implemented
- [ ] OCSF-aligned audit events exportable to SIEM
- [ ] OIDC + SAML + WebAuthn authentication working
- [ ] Policy evaluation <5ms for 100 policies
- [ ] Continuous verification runs at configurable intervals
- [ ] Session recording encrypted and stored in S3-compatible storage
- [ ] AI policy suggestions generated with human-in-the-loop review
- [ ] Natural language policy authoring functional
- [ ] Behavioral baselining and anomaly detection operational
- [ ] Compliance templates for SOC 2, HIPAA, FedRAMP, PCI-DSS, GDPR
- [ ] Rate limiting, security headers, and input validation on all endpoints
- [ ] Graph layer supports blast radius and trust chain queries
- [ ] Multi-tenant isolation verified with integration tests
- [ ] Load testing completed for 10,000 concurrent sessions
- [ ] README, API reference, and architecture documentation complete
