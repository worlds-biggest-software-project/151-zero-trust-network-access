# Data Model Suggestion 1: Entity-Centric Normalized Relational

> Project: Zero Trust Network Access · Created: 2026-05-19

## Philosophy

This model follows a traditional normalized relational approach where every zero trust concept — identities, devices, policies, applications, connectors, sessions — receives its own table with strict foreign key relationships. The design mirrors the NIST SP 800-207 logical architecture directly: Policy Decision Point (PDP), Policy Enforcement Point (PEP), and Policy Information Points (PIPs) each have dedicated entity representations. Reference data (jurisdictions, compliance frameworks, device OS types) is stored in lookup tables with ISO-aligned codes.

The normalized approach ensures referential integrity at every level. A policy rule cannot reference a non-existent application; a session cannot exist without a verified identity and device posture assessment. This is the model that auditors and compliance officers understand best, and it maps cleanly to the SOC 2, HIPAA, FedRAMP, and PCI-DSS evidence requirements described in the project scope. Every relationship is explicit, every constraint is enforced at the database level, and every query can be expressed in standard SQL without JSONB operators or event replay.

The trade-off is table count and migration overhead. Adding a new device posture signal (e.g., TPM attestation) requires a schema migration. Multi-jurisdiction variations in policy structure require either nullable columns or additional junction tables. This model works best for teams that value data integrity over schema agility and expect the domain to stabilize before scaling.

**Best for:** Regulated environments where auditors require explicit relational evidence trails and the policy model is well-understood before deployment.

**Trade-offs:**
- (+) Maximum referential integrity — broken relationships impossible at the database level
- (+) Standard SQL queries — no JSONB operators, no event replay needed
- (+) Maps directly to NIST SP 800-207 logical components (PDP, PEP, PIP)
- (+) Easy to generate compliance reports with JOINs
- (-) High table count (~45-50 tables) increases migration complexity
- (-) Adding new posture signals or policy attributes requires schema changes
- (-) Multi-tenant row-level security adds WHERE clauses to every query
- (-) Jurisdiction-specific policy variations are awkward to model without nullable columns

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| NIST SP 800-207 | PDP, PEP, PIP architecture mapped to `policy_decisions`, `enforcement_points`, and context tables |
| NIST SP 800-207A | Multi-cloud connector model with `connectors` and `connector_networks` tables |
| CISA Zero Trust Maturity Model v2.0 | Five pillars (Identity, Devices, Networks, Apps, Data) map to table groups |
| ISO/IEC 27001:2022 (A.8.20, A.8.22) | Network segmentation controls modeled via `network_segments` and `segment_policies` |
| ISO/IEC 29146:2016 | Access management framework reflected in `access_policies` and `policy_rules` |
| OAuth 2.0 (RFC 6749) / OIDC | Identity provider integration via `identity_providers` and `identity_tokens` |
| SPIFFE | Workload identity via `workload_identities` with SPIFFE ID URI format |
| FIDO2 / WebAuthn | Credential types in `user_credentials` table |
| OCSF | Audit event classification in `audit_events` with OCSF class_uid mapping |
| RFC 7519 (JWT) | Token structure in `session_tokens` table |

---

## Identity & Authentication Domain

### identity_providers

```sql
CREATE TABLE identity_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    provider_type   VARCHAR(50) NOT NULL CHECK (provider_type IN ('saml', 'oidc', 'ldap', 'scim')),
    issuer_url      TEXT NOT NULL,                    -- OIDC issuer or SAML entity ID
    client_id       VARCHAR(255),                     -- OAuth 2.0 client_id
    client_secret_ref VARCHAR(255),                   -- Reference to secrets manager, never stored plaintext
    metadata_url    TEXT,                              -- SAML metadata URL or OIDC .well-known
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_idp_tenant ON identity_providers(tenant_id);
CREATE UNIQUE INDEX idx_idp_tenant_name ON identity_providers(tenant_id, name);
```

### users

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    idp_id          UUID NOT NULL REFERENCES identity_providers(id),
    external_id     VARCHAR(255) NOT NULL,            -- Subject claim from IdP
    email           VARCHAR(320),
    display_name    VARCHAR(255),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_users_tenant_idp_ext ON users(tenant_id, idp_id, external_id);
CREATE INDEX idx_users_email ON users(tenant_id, email);
```

### user_credentials

```sql
CREATE TABLE user_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_type VARCHAR(50) NOT NULL CHECK (credential_type IN (
        'fido2_webauthn', 'totp', 'sms', 'email_otp', 'x509_certificate', 'recovery_code'
    )),
    credential_ref  TEXT NOT NULL,                    -- Public key, cert thumbprint, or hashed secret
    aal_level       SMALLINT NOT NULL DEFAULT 1 CHECK (aal_level BETWEEN 1 AND 3),
                                                      -- NIST SP 800-63B AAL1/AAL2/AAL3
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_used_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_creds_user ON user_credentials(user_id);
```

### groups

```sql
CREATE TABLE groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    source          VARCHAR(50) NOT NULL DEFAULT 'local' CHECK (source IN ('local', 'idp_sync', 'scim')),
    external_id     VARCHAR(255),                     -- Group ID from IdP/SCIM
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_groups_tenant_name ON groups(tenant_id, name);
```

### group_members

```sql
CREATE TABLE group_members (
    group_id        UUID NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    added_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);
```

### roles

```sql
CREATE TABLE roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(100) NOT NULL,
    description     TEXT,
    is_system       BOOLEAN NOT NULL DEFAULT false,   -- Built-in roles (admin, auditor, etc.)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_roles_tenant_name ON roles(tenant_id, name);
```

### role_assignments

```sql
CREATE TABLE role_assignments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    role_id         UUID NOT NULL REFERENCES roles(id),
    principal_type  VARCHAR(20) NOT NULL CHECK (principal_type IN ('user', 'group', 'service_account')),
    principal_id    UUID NOT NULL,                    -- FK to users.id, groups.id, or service_accounts.id
    scope_type      VARCHAR(30) NOT NULL DEFAULT 'tenant' CHECK (scope_type IN ('tenant', 'application', 'network')),
    scope_id        UUID,                             -- NULL for tenant-wide, or specific app/network ID
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ra_principal ON role_assignments(principal_type, principal_id);
CREATE INDEX idx_ra_role ON role_assignments(role_id);
```

---

## Device & Posture Domain

### devices

```sql
CREATE TABLE devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    user_id         UUID REFERENCES users(id),        -- Owner; NULL for shared/kiosk devices
    device_name     VARCHAR(255),
    serial_number   VARCHAR(255),
    os_type         VARCHAR(50) NOT NULL CHECK (os_type IN ('windows', 'macos', 'linux', 'ios', 'android', 'chromeos')),
    os_version      VARCHAR(100),
    hardware_model  VARCHAR(255),
    mdm_enrolled    BOOLEAN NOT NULL DEFAULT false,
    mdm_provider    VARCHAR(100),                     -- Intune, Jamf, etc.
    tpm_present     BOOLEAN,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_devices_tenant_user ON devices(tenant_id, user_id);
CREATE INDEX idx_devices_serial ON devices(tenant_id, serial_number);
```

### device_posture_assessments

```sql
CREATE TABLE device_posture_assessments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id           UUID NOT NULL REFERENCES devices(id),
    assessed_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    os_version_compliant    BOOLEAN NOT NULL,
    disk_encrypted          BOOLEAN NOT NULL,
    firewall_enabled        BOOLEAN NOT NULL,
    antivirus_active        BOOLEAN NOT NULL,
    antivirus_up_to_date    BOOLEAN NOT NULL,
    screen_lock_enabled     BOOLEAN NOT NULL,
    jailbroken              BOOLEAN NOT NULL DEFAULT false,
    overall_score           SMALLINT NOT NULL CHECK (overall_score BETWEEN 0 AND 100),
    overall_compliant       BOOLEAN NOT NULL,
    expires_at              TIMESTAMPTZ NOT NULL          -- Posture assessments have a TTL
);

CREATE INDEX idx_posture_device_time ON device_posture_assessments(device_id, assessed_at DESC);
```

### device_certificates

```sql
CREATE TABLE device_certificates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    certificate_thumbprint VARCHAR(64) NOT NULL,
    issuer          TEXT NOT NULL,
    subject         TEXT NOT NULL,
    not_before      TIMESTAMPTZ NOT NULL,
    not_after       TIMESTAMPTZ NOT NULL,
    is_revoked      BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_devcert_device ON device_certificates(device_id);
CREATE UNIQUE INDEX idx_devcert_thumbprint ON device_certificates(certificate_thumbprint);
```

---

## Application & Network Domain

### applications

```sql
CREATE TABLE applications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    app_type        VARCHAR(50) NOT NULL CHECK (app_type IN (
        'web', 'ssh', 'rdp', 'database', 'kubernetes', 'api', 'tcp_generic', 'udp_generic'
    )),
    internal_host   VARCHAR(255) NOT NULL,            -- Internal hostname or IP
    internal_port   INTEGER NOT NULL,
    external_domain VARCHAR(255),                     -- Public-facing domain (for web apps)
    protocol        VARCHAR(20) NOT NULL DEFAULT 'tcp' CHECK (protocol IN ('tcp', 'udp', 'http', 'https')),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_apps_tenant ON applications(tenant_id);
CREATE UNIQUE INDEX idx_apps_tenant_name ON applications(tenant_id, name);
```

### connectors

```sql
CREATE TABLE connectors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    connector_token_hash VARCHAR(128) NOT NULL,       -- Hashed registration token
    status          VARCHAR(30) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'online', 'offline', 'degraded', 'decommissioned'
    )),
    version         VARCHAR(50),
    cloud_provider  VARCHAR(50),                      -- aws, azure, gcp, on_prem
    region          VARCHAR(100),                     -- ISO 3166-2 or cloud region code
    ip_address      INET,
    last_heartbeat  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_connectors_tenant ON connectors(tenant_id);
CREATE INDEX idx_connectors_status ON connectors(tenant_id, status);
```

### connector_applications

```sql
-- Junction: which connectors can reach which applications
CREATE TABLE connector_applications (
    connector_id    UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    application_id  UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    is_primary      BOOLEAN NOT NULL DEFAULT true,    -- Failover support
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (connector_id, application_id)
);
```

### network_segments

```sql
CREATE TABLE network_segments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    cidr            CIDR NOT NULL,                    -- e.g., 10.0.1.0/24
    description     TEXT,
    environment     VARCHAR(50) CHECK (environment IN ('production', 'staging', 'development', 'dmz')),
    cloud_vpc_id    VARCHAR(255),                     -- AWS VPC, Azure VNet, GCP VPC
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_segments_tenant ON network_segments(tenant_id);
```

### workload_identities

```sql
-- SPIFFE-aligned workload identity for service-to-service zero trust
CREATE TABLE workload_identities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    spiffe_id       TEXT NOT NULL,                     -- spiffe://trust-domain/workload/path
    application_id  UUID REFERENCES applications(id),
    attestation_type VARCHAR(50) NOT NULL CHECK (attestation_type IN (
        'k8s_psat', 'aws_iid', 'azure_msi', 'gcp_iit', 'x509_pop', 'join_token'
    )),
    svid_ttl_seconds INTEGER NOT NULL DEFAULT 3600,   -- Default 1-hour SVID lifetime per SPIFFE best practice
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_workload_spiffe ON workload_identities(tenant_id, spiffe_id);
```

---

## Policy Engine Domain

### access_policies

```sql
CREATE TABLE access_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    action          VARCHAR(20) NOT NULL CHECK (action IN ('allow', 'deny', 'require_mfa', 'require_approval')),
    priority        INTEGER NOT NULL DEFAULT 100,     -- Lower number = higher priority
    is_active       BOOLEAN NOT NULL DEFAULT true,
    compliance_framework VARCHAR(50),                 -- soc2, hipaa, fedramp, pci_dss, gdpr
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policies_tenant ON access_policies(tenant_id);
CREATE INDEX idx_policies_priority ON access_policies(tenant_id, priority);
```

### policy_rules

```sql
-- Individual conditions within a policy (ANDed together)
CREATE TABLE policy_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id       UUID NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
    rule_type       VARCHAR(50) NOT NULL CHECK (rule_type IN (
        'identity_group', 'identity_user', 'device_posture_min_score',
        'device_os_type', 'device_mdm_required', 'time_window',
        'geo_location', 'ip_range', 'mfa_required', 'aal_minimum',
        'application', 'network_segment', 'risk_score_max'
    )),
    operator        VARCHAR(20) NOT NULL DEFAULT 'equals' CHECK (operator IN (
        'equals', 'not_equals', 'in', 'not_in', 'greater_than', 'less_than', 'contains'
    )),
    value           TEXT NOT NULL,                    -- Compared using operator; type depends on rule_type
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_rules_policy ON policy_rules(policy_id);
```

### policy_application_bindings

```sql
-- Which policies apply to which applications
CREATE TABLE policy_application_bindings (
    policy_id       UUID NOT NULL REFERENCES access_policies(id) ON DELETE CASCADE,
    application_id  UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (policy_id, application_id)
);
```

### compliance_templates

```sql
CREATE TABLE compliance_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework       VARCHAR(50) NOT NULL CHECK (framework IN (
        'soc2', 'hipaa', 'fedramp', 'pci_dss_v4', 'gdpr', 'nist_csf_2', 'cisa_ztmm_v2'
    )),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    template_version VARCHAR(20) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_compliance_framework_ver ON compliance_templates(framework, template_version);
```

### compliance_template_rules

```sql
CREATE TABLE compliance_template_rules (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    template_id     UUID NOT NULL REFERENCES compliance_templates(id) ON DELETE CASCADE,
    rule_type       VARCHAR(50) NOT NULL,             -- Same enum as policy_rules.rule_type
    operator        VARCHAR(20) NOT NULL,
    value           TEXT NOT NULL,
    rationale       TEXT                              -- Why this rule satisfies the compliance requirement
);

CREATE INDEX idx_ctr_template ON compliance_template_rules(template_id);
```

---

## Session & Access Domain

### access_sessions

```sql
CREATE TABLE access_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    user_id         UUID NOT NULL REFERENCES users(id),
    device_id       UUID NOT NULL REFERENCES devices(id),
    application_id  UUID NOT NULL REFERENCES applications(id),
    connector_id    UUID REFERENCES connectors(id),
    policy_id       UUID NOT NULL REFERENCES access_policies(id), -- Policy that granted access
    posture_assessment_id UUID NOT NULL REFERENCES device_posture_assessments(id),
    status          VARCHAR(30) NOT NULL DEFAULT 'active' CHECK (status IN (
        'active', 'terminated', 'expired', 'quarantined', 'escalated'
    )),
    risk_score      SMALLINT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    ip_address      INET NOT NULL,
    geo_country     CHAR(2),                          -- ISO 3166-1 alpha-2
    geo_city        VARCHAR(100),
    user_agent      TEXT,
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    termination_reason VARCHAR(50)                    -- timeout, user_logout, policy_violation, admin_kill, quarantined
);

CREATE INDEX idx_sessions_tenant_active ON access_sessions(tenant_id, status) WHERE status = 'active';
CREATE INDEX idx_sessions_user ON access_sessions(user_id, started_at DESC);
CREATE INDEX idx_sessions_app ON access_sessions(application_id, started_at DESC);
```

### session_tokens

```sql
CREATE TABLE session_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES access_sessions(id) ON DELETE CASCADE,
    token_hash      VARCHAR(128) NOT NULL,            -- SHA-256 hash; never store plaintext
    token_type      VARCHAR(20) NOT NULL CHECK (token_type IN ('access', 'refresh')),
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    revoked_at      TIMESTAMPTZ                       -- NULL if still valid
);

CREATE INDEX idx_tokens_session ON session_tokens(session_id);
CREATE INDEX idx_tokens_hash ON session_tokens(token_hash);
```

### session_recordings

```sql
CREATE TABLE session_recordings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES access_sessions(id),
    recording_type  VARCHAR(20) NOT NULL CHECK (recording_type IN ('ssh', 'rdp', 'database_query')),
    storage_uri     TEXT NOT NULL,                    -- S3/GCS/Azure Blob URI
    file_size_bytes BIGINT,
    duration_seconds INTEGER,
    encryption_key_ref VARCHAR(255) NOT NULL,         -- KMS key reference
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_recordings_session ON session_recordings(session_id);
```

### session_verifications

```sql
-- Mid-session continuous verification checks (ZTNA 2.0 pattern)
CREATE TABLE session_verifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES access_sessions(id),
    verified_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    posture_assessment_id UUID REFERENCES device_posture_assessments(id),
    risk_score      SMALLINT NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    ip_changed      BOOLEAN NOT NULL DEFAULT false,
    geo_changed     BOOLEAN NOT NULL DEFAULT false,
    result          VARCHAR(20) NOT NULL CHECK (result IN ('pass', 'warn', 'fail', 'quarantine')),
    action_taken    VARCHAR(30)                       -- none, risk_elevated, mfa_prompted, session_terminated, escalated
);

CREATE INDEX idx_verifications_session ON session_verifications(session_id, verified_at DESC);
```

---

## Audit & Compliance Domain

### audit_events

```sql
CREATE TABLE audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    event_time      TIMESTAMPTZ NOT NULL DEFAULT now(),
    ocsf_class_uid  INTEGER NOT NULL,                 -- OCSF event class (e.g., 300201 for Authentication)
    ocsf_activity_id SMALLINT NOT NULL,               -- OCSF activity within class
    severity        SMALLINT NOT NULL DEFAULT 1 CHECK (severity BETWEEN 0 AND 5),
                                                      -- OCSF severity: 0=Unknown, 1=Info, 2=Low, 3=Med, 4=High, 5=Critical
    actor_type      VARCHAR(30) NOT NULL CHECK (actor_type IN ('user', 'service_account', 'system', 'admin')),
    actor_id        UUID,
    resource_type   VARCHAR(50) NOT NULL,             -- policy, application, connector, session, user, device, etc.
    resource_id     UUID,
    action          VARCHAR(100) NOT NULL,            -- e.g., session.created, policy.updated, device.quarantined
    outcome         VARCHAR(20) NOT NULL CHECK (outcome IN ('success', 'failure', 'error', 'unknown')),
    ip_address      INET,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (event_time);

-- Monthly partitions for retention management
CREATE TABLE audit_events_2026_05 PARTITION OF audit_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE audit_events_2026_06 PARTITION OF audit_events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE INDEX idx_audit_tenant_time ON audit_events(tenant_id, event_time DESC);
CREATE INDEX idx_audit_actor ON audit_events(actor_type, actor_id, event_time DESC);
CREATE INDEX idx_audit_resource ON audit_events(resource_type, resource_id, event_time DESC);
CREATE INDEX idx_audit_action ON audit_events(action, event_time DESC);
```

### policy_decisions

```sql
-- Record of every PDP decision (NIST SP 800-207 Policy Decision Point log)
CREATE TABLE policy_decisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    decision_time   TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_id         UUID REFERENCES users(id),
    device_id       UUID REFERENCES devices(id),
    application_id  UUID REFERENCES applications(id),
    matched_policy_id UUID REFERENCES access_policies(id),
    decision        VARCHAR(20) NOT NULL CHECK (decision IN ('allow', 'deny', 'challenge', 'quarantine')),
    risk_score      SMALLINT NOT NULL,
    posture_score   SMALLINT,
    aal_level       SMALLINT,
    evaluation_ms   INTEGER,                          -- How long the decision took
    ip_address      INET,
    geo_country     CHAR(2)
) PARTITION BY RANGE (decision_time);

CREATE TABLE policy_decisions_2026_05 PARTITION OF policy_decisions
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE INDEX idx_pd_tenant_time ON policy_decisions(tenant_id, decision_time DESC);
CREATE INDEX idx_pd_user ON policy_decisions(user_id, decision_time DESC);
CREATE INDEX idx_pd_decision ON policy_decisions(decision, decision_time DESC);
```

---

## Multi-Tenant & Platform Domain

### tenants

```sql
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) NOT NULL UNIQUE,     -- URL-safe tenant identifier
    plan            VARCHAR(50) NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'starter', 'business', 'enterprise')),
    max_users       INTEGER NOT NULL DEFAULT 50,
    max_connectors  INTEGER NOT NULL DEFAULT 2,
    data_region     VARCHAR(20) NOT NULL DEFAULT 'us' CHECK (data_region IN ('us', 'eu', 'ap', 'au')),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_tenants_slug ON tenants(slug);
```

### service_accounts

```sql
CREATE TABLE service_accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    api_key_hash    VARCHAR(128) NOT NULL,
    scopes          TEXT[] NOT NULL DEFAULT '{}',      -- Array of permitted API scopes
    is_active       BOOLEAN NOT NULL DEFAULT true,
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sa_tenant ON service_accounts(tenant_id);
```

---

## AI & Analytics Domain

### behavioral_baselines

```sql
CREATE TABLE behavioral_baselines (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id),
    baseline_type   VARCHAR(50) NOT NULL CHECK (baseline_type IN (
        'login_time', 'geo_pattern', 'app_usage', 'session_duration', 'data_volume'
    )),
    baseline_data   JSONB NOT NULL,                   -- Statistical model parameters
    confidence      REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    samples_count   INTEGER NOT NULL,
    computed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until     TIMESTAMPTZ NOT NULL
);

CREATE INDEX idx_baselines_user ON behavioral_baselines(user_id, baseline_type);
```

### anomaly_detections

```sql
CREATE TABLE anomaly_detections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    user_id         UUID REFERENCES users(id),
    device_id       UUID REFERENCES devices(id),
    session_id      UUID REFERENCES access_sessions(id),
    detection_type  VARCHAR(50) NOT NULL CHECK (detection_type IN (
        'impossible_travel', 'unusual_time', 'new_device', 'risk_score_spike',
        'unusual_app', 'data_exfiltration', 'brute_force', 'credential_stuffing'
    )),
    severity        SMALLINT NOT NULL CHECK (severity BETWEEN 1 AND 5),
    confidence      REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    details         TEXT,
    remediation     VARCHAR(50),                      -- Action taken: none, mfa_prompted, session_killed, user_locked
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX idx_anomaly_tenant_time ON anomaly_detections(tenant_id, detected_at DESC);
CREATE INDEX idx_anomaly_user ON anomaly_detections(user_id, detected_at DESC);
```

### ai_policy_suggestions

```sql
-- AI-generated policy recommendations from observed access patterns
CREATE TABLE ai_policy_suggestions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    suggested_policy_name VARCHAR(255) NOT NULL,
    suggested_action VARCHAR(20) NOT NULL,
    suggested_rules JSONB NOT NULL,                   -- Array of {rule_type, operator, value} objects
    rationale       TEXT NOT NULL,                     -- Human-readable explanation
    confidence      REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    based_on_sessions INTEGER NOT NULL,               -- How many sessions informed this suggestion
    status          VARCHAR(30) NOT NULL DEFAULT 'pending' CHECK (status IN (
        'pending', 'accepted', 'rejected', 'modified', 'expired'
    )),
    reviewed_by     UUID REFERENCES users(id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at     TIMESTAMPTZ
);

CREATE INDEX idx_ai_suggestions_tenant ON ai_policy_suggestions(tenant_id, status, created_at DESC);
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Multi-Tenant & Platform | 2 | tenants, service_accounts |
| Identity & Authentication | 6 | identity_providers, users, user_credentials, groups, group_members, roles, role_assignments |
| Device & Posture | 3 | devices, device_posture_assessments, device_certificates |
| Application & Network | 5 | applications, connectors, connector_applications, network_segments, workload_identities |
| Policy Engine | 5 | access_policies, policy_rules, policy_application_bindings, compliance_templates, compliance_template_rules |
| Session & Access | 4 | access_sessions, session_tokens, session_recordings, session_verifications |
| Audit & Compliance | 2 | audit_events (partitioned), policy_decisions (partitioned) |
| AI & Analytics | 3 | behavioral_baselines, anomaly_detections, ai_policy_suggestions |
| **Total** | **30** | Plus partition tables for time-series data |

---

## Key Design Decisions

1. **UUID primary keys everywhere** — enables distributed ID generation across connectors and edge nodes without central coordination; aligns with modern SaaS practice.

2. **Tenant isolation via foreign keys** — every query-path table includes `tenant_id` with an index, supporting row-level security (`SET app.current_tenant = '...'` + RLS policies) for multi-tenant isolation.

3. **Separate posture assessments from devices** — device_posture_assessments is append-only with TTL, allowing historical posture queries ("was this device compliant when session X started?") while keeping the devices table as current state.

4. **OCSF-aligned audit events** — using OCSF `class_uid` and `activity_id` ensures audit logs can be exported directly to AWS Security Lake, Splunk, or any OCSF-compatible SIEM without transformation.

5. **Partitioned time-series tables** — audit_events and policy_decisions are partitioned by month for efficient retention management (drop old partitions) and query performance on time-range scans.

6. **Policy rules as separate rows (not JSONB)** — each condition in a policy is a row in policy_rules, enabling SQL-based policy analysis ("which policies require MFA?", "which policies apply to the finance group?") without JSONB containment queries.

7. **SPIFFE workload identity first-class** — workload_identities table stores SPIFFE IDs with attestation types, supporting the service-to-service zero trust use case described in the v1.1 feature scope.

8. **Secrets never stored plaintext** — client_secret_ref, api_key_hash, token_hash, and credential_ref all store references or hashes, never raw secrets. Encryption key references point to an external KMS.

9. **Continuous verification modeled explicitly** — session_verifications table captures every mid-session re-evaluation, supporting the ZTNA 2.0 continuous trust pattern and providing evidence for compliance audits.

10. **AI suggestions require human review** — ai_policy_suggestions has a status workflow (pending → accepted/rejected) ensuring the human-in-the-loop pattern for AI-generated policy changes.
