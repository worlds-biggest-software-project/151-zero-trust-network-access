# Data Model Suggestion 3: Hybrid Relational + JSONB

> Project: Zero Trust Network Access · Created: 2026-05-19

## Philosophy

This model uses a relational backbone for core identity, session, and relationship data, but stores variable and extensible attributes in JSONB columns. The key insight for ZTNA is that device posture signals, policy rule conditions, IdP-specific claims, and jurisdiction-specific compliance requirements vary enormously across deployments. A normalized model requires schema migrations whenever a new posture signal (e.g., TPM 2.0 attestation) or policy condition type (e.g., risk score from a third-party feed) is added. The hybrid approach keeps stable, high-cardinality, frequently-joined columns as relational fields while putting variable, deployment-specific, and evolving attributes in JSONB.

This is the pattern used by modern SaaS platforms like Cloudflare Access and Tailscale internally: the core entity graph (users, devices, policies, sessions) is relational, but the specifics of what constitutes a "policy rule" or a "posture check" are encoded as structured JSON. The Terraform providers for Zscaler, Cloudflare, and Palo Alto all model policy rules as nested JSON objects in their API schemas, suggesting the underlying storage follows a similar pattern.

The hybrid approach is particularly well-suited to ZTNA because the domain spans multiple deployment contexts: a healthcare customer needs HIPAA-specific posture checks; a financial customer needs PCI-DSS specific network segmentation rules; a government customer needs FedRAMP-specific continuous monitoring intervals. Rather than trying to anticipate all variations in the relational schema, the JSONB columns absorb this variation while the relational structure ensures referential integrity where it matters most (a session always references a real user, device, and application).

**Best for:** Rapid MVP development where the policy model and posture signals will evolve significantly; multi-region deployments where compliance requirements vary by jurisdiction.

**Trade-offs:**
- (+) Schema evolution without migrations — new posture signals, policy conditions, or metadata fields are added as JSONB keys
- (+) Fewer tables (~20) than fully normalized (~30), simpler to understand
- (+) JSONB containment queries (`@>`) are efficient with GIN indexes
- (+) Maps naturally to REST API payloads (JSON in, JSON stored, JSON out)
- (+) Multi-jurisdiction variations absorbed by JSONB without nullable column proliferation
- (-) Partial loss of referential integrity — JSONB content is not FK-constrained
- (-) JSONB schema validation must happen at the application layer (or via CHECK constraints)
- (-) Complex queries mixing relational JOINs and JSONB operators can be harder to optimize
- (-) JSONB columns can become "junk drawers" without strict application-layer governance
- (-) Slightly larger storage footprint due to repeated key names in JSONB

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| NIST SP 800-207 | PDP context signals stored as JSONB in policy_decisions; PIP data in JSONB metadata |
| NIST SP 800-207A | Cloud-specific attributes in connector `config` JSONB (VPC IDs, security groups) |
| CISA Zero Trust Maturity Model v2.0 | Maturity pillar scores as JSONB in tenant settings |
| ISO/IEC 27001:2022 | Compliance evidence stored as JSONB arrays of satisfied controls |
| OCSF | Audit events use JSONB `event_data` matching OCSF schema directly |
| OAuth 2.0 / OIDC | IdP-specific claims stored in JSONB on user and session records |
| SPIFFE | Workload identity selectors stored as JSONB arrays matching SPIRE registration entries |
| FIDO2 / WebAuthn | Credential metadata (public key parameters, attestation) in JSONB |
| OPA / Rego | Policy rules stored as structured JSONB matching OPA input document format |

---

## Identity Domain

### tenants

```sql
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) NOT NULL UNIQUE,
    plan            VARCHAR(50) NOT NULL DEFAULT 'free',
    settings        JSONB NOT NULL DEFAULT '{}',
    -- settings example:
    -- {
    --   "max_users": 50,
    --   "max_connectors": 2,
    --   "data_region": "us",
    --   "session_max_duration_hours": 24,
    --   "posture_check_interval_minutes": 15,
    --   "mfa_required_aal": 2,
    --   "compliance_frameworks": ["soc2", "hipaa"],
    --   "cisa_ztmm_maturity": {
    --     "identity": "advanced",
    --     "devices": "initial",
    --     "networks": "advanced",
    --     "applications": "initial",
    --     "data": "traditional"
    --   }
    -- }
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### identity_providers

```sql
CREATE TABLE identity_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    provider_type   VARCHAR(50) NOT NULL,              -- saml, oidc, ldap, scim
    config          JSONB NOT NULL,
    -- config example (OIDC):
    -- {
    --   "issuer_url": "https://accounts.google.com",
    --   "client_id": "abc123.apps.googleusercontent.com",
    --   "client_secret_ref": "vault:secret/idp/google#client_secret",
    --   "scopes": ["openid", "email", "profile", "groups"],
    --   "claim_mappings": {
    --     "email": "email",
    --     "groups": "groups",
    --     "display_name": "name"
    --   },
    --   "allowed_domains": ["company.com"]
    -- }
    -- config example (SAML):
    -- {
    --   "entity_id": "https://idp.company.com/saml",
    --   "sso_url": "https://idp.company.com/saml/sso",
    --   "metadata_url": "https://idp.company.com/saml/metadata",
    --   "certificate_thumbprint": "sha256:abc...",
    --   "attribute_mappings": {
    --     "email": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    --     "groups": "http://schemas.xmlsoap.org/claims/Group"
    --   }
    -- }
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_idp_tenant ON identity_providers(tenant_id);
```

### users

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    idp_id          UUID NOT NULL REFERENCES identity_providers(id),
    external_id     VARCHAR(255) NOT NULL,
    email           VARCHAR(320),
    display_name    VARCHAR(255),
    is_active       BOOLEAN NOT NULL DEFAULT true,
    idp_claims      JSONB NOT NULL DEFAULT '{}',
    -- idp_claims example:
    -- {
    --   "groups": ["engineering", "platform-team"],
    --   "department": "Engineering",
    --   "manager": "jane.doe@company.com",
    --   "office_location": "San Francisco",
    --   "employee_type": "full_time",
    --   "cost_center": "ENG-001"
    -- }
    credentials     JSONB NOT NULL DEFAULT '[]',
    -- credentials example:
    -- [
    --   {"type": "fido2_webauthn", "ref": "pk-hash-abc", "aal": 2, "added_at": "2026-01-15T10:00:00Z"},
    --   {"type": "totp", "ref": "totp-hash-def", "aal": 2, "added_at": "2026-02-01T09:00:00Z"}
    -- ]
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_users_tenant_idp_ext ON users(tenant_id, idp_id, external_id);
CREATE INDEX idx_users_email ON users(tenant_id, email);
CREATE INDEX idx_users_claims_groups ON users USING GIN ((idp_claims->'groups'));
```

### groups

```sql
CREATE TABLE groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    source          VARCHAR(50) NOT NULL DEFAULT 'local',
    external_id     VARCHAR(255),
    metadata        JSONB NOT NULL DEFAULT '{}',
    -- metadata example:
    -- {
    --   "description": "Platform engineering team",
    --   "idp_group_dn": "CN=platform-eng,OU=Groups,DC=company,DC=com",
    --   "auto_sync": true,
    --   "sync_interval_minutes": 60
    -- }
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

---

## Device Domain

### devices

```sql
CREATE TABLE devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    user_id         UUID REFERENCES users(id),
    device_name     VARCHAR(255),
    serial_number   VARCHAR(255),
    os_type         VARCHAR(50) NOT NULL,
    os_version      VARCHAR(100),
    hardware_info   JSONB NOT NULL DEFAULT '{}',
    -- hardware_info example:
    -- {
    --   "model": "MacBookPro18,1",
    --   "manufacturer": "Apple",
    --   "processor": "Apple M1 Pro",
    --   "ram_gb": 32,
    --   "tpm_version": null,
    --   "secure_enclave": true,
    --   "bios_version": "429.120.6"
    -- }
    mdm_info        JSONB NOT NULL DEFAULT '{}',
    -- mdm_info example:
    -- {
    --   "enrolled": true,
    --   "provider": "jamf",
    --   "enrollment_date": "2025-09-15",
    --   "management_id": "jamf-device-12345",
    --   "supervised": true,
    --   "compliance_status": "compliant"
    -- }
    latest_posture  JSONB NOT NULL DEFAULT '{}',
    -- latest_posture example:
    -- {
    --   "assessed_at": "2026-05-19T14:30:00Z",
    --   "expires_at": "2026-05-19T15:30:00Z",
    --   "overall_score": 95,
    --   "overall_compliant": true,
    --   "checks": {
    --     "os_version_compliant": true,
    --     "disk_encrypted": true,
    --     "firewall_enabled": true,
    --     "antivirus_active": true,
    --     "antivirus_definitions_age_hours": 4,
    --     "screen_lock_enabled": true,
    --     "screen_lock_timeout_seconds": 300,
    --     "jailbroken": false,
    --     "certificate_valid": true,
    --     "certificate_expires_at": "2027-01-15T00:00:00Z"
    --   },
    --   "custom_checks": {
    --     "crowdstrike_running": true,
    --     "zscaler_client_version": "4.2.1"
    --   }
    -- }
    is_active       BOOLEAN NOT NULL DEFAULT true,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_devices_tenant ON devices(tenant_id);
CREATE INDEX idx_devices_user ON devices(user_id);
CREATE INDEX idx_devices_posture ON devices USING GIN (latest_posture);
```

### device_posture_history

```sql
-- Append-only posture assessment history for audit
CREATE TABLE device_posture_history (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       UUID NOT NULL REFERENCES devices(id),
    assessed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    posture_data    JSONB NOT NULL,                    -- Same structure as devices.latest_posture
    triggered_by    VARCHAR(50) NOT NULL DEFAULT 'scheduled'
                    CHECK (triggered_by IN ('scheduled', 'session_start', 'mid_session', 'manual', 'mdm_event'))
) PARTITION BY RANGE (assessed_at);

CREATE TABLE device_posture_history_2026_05 PARTITION OF device_posture_history
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE INDEX idx_posture_history_device ON device_posture_history(device_id, assessed_at DESC);
```

---

## Application & Network Domain

### applications

```sql
CREATE TABLE applications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    app_type        VARCHAR(50) NOT NULL,              -- web, ssh, rdp, database, kubernetes, api, tcp, udp
    connection      JSONB NOT NULL,
    -- connection example (web app):
    -- {
    --   "internal_host": "app.internal.company.com",
    --   "internal_port": 443,
    --   "protocol": "https",
    --   "external_domain": "app.company.com",
    --   "tls_verify": true,
    --   "health_check_path": "/healthz",
    --   "health_check_interval_seconds": 30
    -- }
    -- connection example (SSH):
    -- {
    --   "internal_host": "bastion.internal",
    --   "internal_port": 22,
    --   "protocol": "ssh",
    --   "session_recording": true,
    --   "allowed_commands": ["bash", "zsh"],
    --   "max_session_duration_minutes": 480
    -- }
    -- connection example (Kubernetes):
    -- {
    --   "cluster_name": "prod-us-east-1",
    --   "api_server": "https://k8s.internal:6443",
    --   "namespace_restrictions": ["default", "app-*"],
    --   "allowed_resources": ["pods", "services", "deployments"],
    --   "allowed_verbs": ["get", "list", "watch"]
    -- }
    -- connection example (database):
    -- {
    --   "internal_host": "postgres-primary.internal",
    --   "internal_port": 5432,
    --   "protocol": "postgresql",
    --   "database_name": "production",
    --   "tls_required": true,
    --   "query_logging": true,
    --   "max_query_duration_seconds": 300
    -- }
    tags            JSONB NOT NULL DEFAULT '[]',       -- ["production", "pci-scope", "us-east-1"]
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_apps_tenant ON applications(tenant_id);
CREATE UNIQUE INDEX idx_apps_tenant_name ON applications(tenant_id, name);
CREATE INDEX idx_apps_tags ON applications USING GIN (tags);
```

### connectors

```sql
CREATE TABLE connectors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    status          VARCHAR(30) NOT NULL DEFAULT 'pending',
    config          JSONB NOT NULL DEFAULT '{}',
    -- config example:
    -- {
    --   "version": "1.4.2",
    --   "cloud_provider": "aws",
    --   "region": "us-east-1",
    --   "vpc_id": "vpc-abc123",
    --   "subnet_ids": ["subnet-a1", "subnet-b2"],
    --   "security_group_id": "sg-xyz789",
    --   "instance_type": "t3.medium",
    --   "auto_update": true,
    --   "log_level": "info",
    --   "max_concurrent_sessions": 1000,
    --   "tls_min_version": "1.3"
    -- }
    linked_app_ids  UUID[] NOT NULL DEFAULT '{}',      -- Applications this connector serves
    last_heartbeat  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_connectors_tenant ON connectors(tenant_id);
CREATE INDEX idx_connectors_status ON connectors(tenant_id, status);
```

### workload_identities

```sql
CREATE TABLE workload_identities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    spiffe_id       TEXT NOT NULL,                     -- spiffe://trust-domain/workload/path
    application_id  UUID REFERENCES applications(id),
    attestation     JSONB NOT NULL,
    -- attestation example (Kubernetes):
    -- {
    --   "type": "k8s_psat",
    --   "namespace": "production",
    --   "service_account": "api-server",
    --   "pod_label_selectors": {"app": "api-server", "version": "v2"},
    --   "svid_ttl_seconds": 3600
    -- }
    -- attestation example (AWS):
    -- {
    --   "type": "aws_iid",
    --   "account_id": "123456789012",
    --   "region": "us-east-1",
    --   "instance_tags": {"Role": "api-server"},
    --   "svid_ttl_seconds": 3600
    -- }
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_workload_spiffe ON workload_identities(tenant_id, spiffe_id);
```

---

## Policy Domain

### access_policies

```sql
CREATE TABLE access_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    action          VARCHAR(20) NOT NULL,              -- allow, deny, require_mfa, require_approval
    priority        INTEGER NOT NULL DEFAULT 100,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    rules           JSONB NOT NULL DEFAULT '[]',
    -- rules example:
    -- [
    --   {"type": "identity_group", "op": "in", "value": ["engineering", "devops"]},
    --   {"type": "device_posture_min_score", "op": "gte", "value": 80},
    --   {"type": "device_os_type", "op": "in", "value": ["macos", "linux"]},
    --   {"type": "mfa_required", "op": "eq", "value": true},
    --   {"type": "aal_minimum", "op": "gte", "value": 2},
    --   {"type": "time_window", "op": "in", "value": {"days": ["mon","tue","wed","thu","fri"], "hours": "09:00-18:00", "tz": "America/New_York"}},
    --   {"type": "geo_country", "op": "in", "value": ["US", "CA", "GB"]},
    --   {"type": "ip_range", "op": "in", "value": ["10.0.0.0/8", "203.0.113.0/24"]},
    --   {"type": "risk_score_max", "op": "lte", "value": 50}
    -- ]
    bound_applications UUID[] NOT NULL DEFAULT '{}',   -- Application IDs this policy applies to
    compliance_framework VARCHAR(50),
    metadata        JSONB NOT NULL DEFAULT '{}',
    -- metadata example:
    -- {
    --   "compliance_controls": ["AC-3", "AC-6", "IA-2"],
    --   "review_required_by": "2026-06-19",
    --   "last_reviewed_by": "uuid-of-reviewer",
    --   "natural_language_source": "Allow engineers to SSH into production during business hours from US/CA/UK"
    -- }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policies_tenant ON access_policies(tenant_id);
CREATE INDEX idx_policies_priority ON access_policies(tenant_id, priority);
CREATE INDEX idx_policies_apps ON access_policies USING GIN (bound_applications);
CREATE INDEX idx_policies_rules ON access_policies USING GIN (rules);
```

### compliance_templates

```sql
CREATE TABLE compliance_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework       VARCHAR(50) NOT NULL,              -- soc2, hipaa, fedramp, pci_dss_v4, gdpr
    name            VARCHAR(255) NOT NULL,
    version         VARCHAR(20) NOT NULL,
    template_rules  JSONB NOT NULL,
    -- template_rules example:
    -- {
    --   "required_rules": [
    --     {"type": "mfa_required", "op": "eq", "value": true, "rationale": "HIPAA §164.312(d) - Person or entity authentication"},
    --     {"type": "device_posture_min_score", "op": "gte", "value": 70, "rationale": "HIPAA §164.310(d)(1) - Device and media controls"},
    --     {"type": "aal_minimum", "op": "gte", "value": 2, "rationale": "NIST SP 800-63B AAL2 for ePHI access"}
    --   ],
    --   "recommended_rules": [
    --     {"type": "time_window", "op": "in", "value": {"days": ["mon","tue","wed","thu","fri"]}, "rationale": "Reduce after-hours access risk"}
    --   ],
    --   "session_settings": {
    --     "max_duration_hours": 8,
    --     "verification_interval_minutes": 15,
    --     "session_recording": true
    --   }
    -- }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_templates_framework ON compliance_templates(framework, version);
```

---

## Session Domain

### access_sessions

```sql
CREATE TABLE access_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    user_id         UUID NOT NULL REFERENCES users(id),
    device_id       UUID NOT NULL REFERENCES devices(id),
    application_id  UUID NOT NULL REFERENCES applications(id),
    connector_id    UUID REFERENCES connectors(id),
    policy_id       UUID NOT NULL REFERENCES access_policies(id),
    status          VARCHAR(30) NOT NULL DEFAULT 'active',
    risk_score      SMALLINT NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    context         JSONB NOT NULL DEFAULT '{}',
    -- context example:
    -- {
    --   "ip_address": "203.0.113.42",
    --   "geo": {"country": "US", "region": "CA", "city": "San Francisco", "lat": 37.77, "lon": -122.42},
    --   "user_agent": "Mozilla/5.0...",
    --   "aal_level": 2,
    --   "posture_score_at_start": 95,
    --   "matched_rules": [
    --     {"type": "identity_group", "matched": "engineering"},
    --     {"type": "device_posture_min_score", "score": 95}
    --   ],
    --   "token_expires_at": "2026-05-19T22:00:00Z"
    -- }
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    termination_reason VARCHAR(50),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sessions_tenant_active ON access_sessions(tenant_id, status) WHERE status = 'active';
CREATE INDEX idx_sessions_user ON access_sessions(user_id, started_at DESC);
CREATE INDEX idx_sessions_app ON access_sessions(application_id, started_at DESC);
```

### session_verifications

```sql
CREATE TABLE session_verifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES access_sessions(id),
    verified_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    result          VARCHAR(20) NOT NULL,              -- pass, warn, fail, quarantine
    verification_data JSONB NOT NULL,
    -- verification_data example:
    -- {
    --   "risk_score": 15,
    --   "posture_score": 95,
    --   "ip_changed": false,
    --   "geo_changed": false,
    --   "ip_address": "203.0.113.42",
    --   "geo": {"country": "US", "city": "San Francisco"},
    --   "action_taken": "none",
    --   "device_posture_checks": {
    --     "disk_encrypted": true,
    --     "antivirus_active": true
    --   }
    -- }
    action_taken    VARCHAR(30)
);

CREATE INDEX idx_verifications_session ON session_verifications(session_id, verified_at DESC);
```

### session_recordings

```sql
CREATE TABLE session_recordings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id      UUID NOT NULL REFERENCES access_sessions(id),
    recording_type  VARCHAR(20) NOT NULL,
    storage_uri     TEXT NOT NULL,
    metadata        JSONB NOT NULL DEFAULT '{}',
    -- metadata example:
    -- {
    --   "file_size_bytes": 1048576,
    --   "duration_seconds": 3600,
    --   "encryption_key_ref": "kms:us-east-1:key/abc123",
    --   "codec": "asciicast",
    --   "commands_count": 47,
    --   "has_sensitive_content": false
    -- }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_recordings_session ON session_recordings(session_id);
```

---

## Audit Domain

### audit_events

```sql
CREATE TABLE audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type      VARCHAR(100) NOT NULL,
    severity        SMALLINT NOT NULL DEFAULT 1,
    actor           JSONB NOT NULL,
    -- actor example:
    -- {
    --   "type": "user",
    --   "id": "uuid",
    --   "email": "jane@company.com",
    --   "ip_address": "203.0.113.42",
    --   "user_agent": "Mozilla/5.0..."
    -- }
    resource        JSONB NOT NULL,
    -- resource example:
    -- {
    --   "type": "policy",
    --   "id": "uuid",
    --   "name": "Engineering SSH Access"
    -- }
    event_data      JSONB NOT NULL DEFAULT '{}',
    -- event_data carries the OCSF-compatible full event payload
    ocsf_class_uid  INTEGER,
    outcome         VARCHAR(20) NOT NULL
) PARTITION BY RANGE (event_time);

CREATE TABLE audit_events_2026_05 PARTITION OF audit_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE INDEX idx_audit_tenant_time ON audit_events(tenant_id, event_time DESC);
CREATE INDEX idx_audit_type ON audit_events(event_type, event_time DESC);
CREATE INDEX idx_audit_actor ON audit_events USING GIN (actor);
CREATE INDEX idx_audit_resource ON audit_events USING GIN (resource);
```

### policy_decisions

```sql
CREATE TABLE policy_decisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    decision_time   TIMESTAMPTZ NOT NULL DEFAULT now(),
    decision        VARCHAR(20) NOT NULL,
    evaluation      JSONB NOT NULL,
    -- evaluation example:
    -- {
    --   "user_id": "uuid",
    --   "device_id": "uuid",
    --   "application_id": "uuid",
    --   "matched_policy_id": "uuid",
    --   "risk_score": 12,
    --   "posture_score": 95,
    --   "aal_level": 2,
    --   "ip_address": "203.0.113.42",
    --   "geo_country": "US",
    --   "evaluation_ms": 23,
    --   "evaluated_policies": [
    --     {"policy_id": "uuid", "result": "match", "priority": 100},
    --     {"policy_id": "uuid", "result": "no_match", "priority": 200}
    --   ],
    --   "rule_evaluations": [
    --     {"type": "identity_group", "result": true, "matched": "engineering"},
    --     {"type": "device_posture_min_score", "result": true, "actual": 95, "required": 80}
    --   ]
    -- }
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
) PARTITION BY RANGE (decision_time);

CREATE TABLE policy_decisions_2026_05 PARTITION OF policy_decisions
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE INDEX idx_pd_tenant_time ON policy_decisions(tenant_id, decision_time DESC);
CREATE INDEX idx_pd_decision ON policy_decisions(decision, decision_time DESC);
CREATE INDEX idx_pd_evaluation ON policy_decisions USING GIN (evaluation);
```

---

## AI & Analytics Domain

### ai_insights

```sql
CREATE TABLE ai_insights (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    insight_type    VARCHAR(50) NOT NULL,              -- policy_suggestion, anomaly, behavioral_baseline, risk_forecast
    status          VARCHAR(30) NOT NULL DEFAULT 'pending',
    insight_data    JSONB NOT NULL,
    -- insight_data example (policy_suggestion):
    -- {
    --   "suggested_name": "Restrict contractor billing access to business hours",
    --   "suggested_action": "allow",
    --   "suggested_rules": [
    --     {"type": "identity_group", "op": "eq", "value": "contractors"},
    --     {"type": "time_window", "op": "in", "value": {"days": ["mon","tue","wed","thu","fri"], "hours": "09:00-17:00"}}
    --   ],
    --   "confidence": 0.87,
    --   "based_on_sessions": 1247,
    --   "natural_language": "Allow contractors to access the billing dashboard between 9-5 on weekdays",
    --   "rationale": "97% of contractor billing sessions occur within this window"
    -- }
    -- insight_data example (anomaly):
    -- {
    --   "detection_type": "impossible_travel",
    --   "user_id": "uuid",
    --   "session_id": "uuid",
    --   "severity": 4,
    --   "confidence": 0.92,
    --   "details": {
    --     "previous_location": {"country": "US", "city": "San Francisco"},
    --     "current_location": {"country": "RU", "city": "Moscow"},
    --     "time_gap_minutes": 45,
    --     "distance_km": 9500
    --   },
    --   "recommended_action": "quarantine_session"
    -- }
    reviewed_by     UUID REFERENCES users(id),
    reviewed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_insights_tenant ON ai_insights(tenant_id, insight_type, status, created_at DESC);
CREATE INDEX idx_insights_data ON ai_insights USING GIN (insight_data);
```

---

## Example Queries

### Find all policies requiring MFA for a specific application

```sql
SELECT id, name, action, rules, priority
FROM access_policies
WHERE tenant_id = :tenant_id
  AND :app_id = ANY(bound_applications)
  AND rules @> '[{"type": "mfa_required", "op": "eq", "value": true}]'
  AND is_active = true
ORDER BY priority ASC;
```

### Find all devices with non-compliant posture

```sql
SELECT id, device_name, os_type,
       latest_posture->>'overall_score' AS score,
       latest_posture->'checks' AS failed_checks
FROM devices
WHERE tenant_id = :tenant_id
  AND (latest_posture->>'overall_compliant')::boolean = false
  AND is_active = true;
```

### Find users in a specific IdP group with FIDO2 credentials

```sql
SELECT id, email, display_name, credentials
FROM users
WHERE tenant_id = :tenant_id
  AND idp_claims->'groups' ? 'engineering'
  AND credentials @> '[{"type": "fido2_webauthn"}]';
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Identity | 4 | tenants, identity_providers, users, groups + group_members junction |
| Device | 2 | devices (with JSONB posture), device_posture_history (partitioned) |
| Application & Network | 3 | applications, connectors, workload_identities |
| Policy | 2 | access_policies (rules as JSONB), compliance_templates |
| Session | 3 | access_sessions, session_verifications, session_recordings |
| Audit | 2 | audit_events (partitioned), policy_decisions (partitioned) |
| AI & Analytics | 1 | ai_insights (unified JSONB) |
| **Total** | **18** | Plus partition tables; ~40% fewer than normalized model |

---

## Key Design Decisions

1. **Policy rules as JSONB array, not separate table** — the `rules` column on access_policies stores all conditions as a JSON array. This matches how policies are authored in the UI (as a single document), how they are evaluated by the policy engine (deserialized into a rule evaluator), and how they are exposed via the REST API. GIN index enables containment queries. Trade-off: no FK validation on group/user references inside rules.

2. **Device posture as JSONB with extensible checks** — `latest_posture` on the devices table stores the current posture snapshot as JSONB. This absorbs new posture signals (TPM attestation, EDR status, custom checks) without schema changes. The `device_posture_history` table preserves the full assessment history.

3. **IdP claims preserved verbatim** — `idp_claims` on users stores the full set of claims from the identity provider as JSONB. This avoids mapping every possible SAML attribute or OIDC claim to a relational column, and enables policy rules that reference arbitrary claims (e.g., department, cost center, office location).

4. **Application connection details as JSONB** — the `connection` column on applications holds protocol-specific configuration. A web app, SSH server, database, and Kubernetes cluster all have fundamentally different connection parameters. JSONB absorbs this variation with a single column.

5. **Unified AI insights table** — instead of separate tables for anomaly detections, policy suggestions, and behavioral baselines, a single `ai_insights` table with `insight_type` discriminator and JSONB payload handles all AI outputs. This simplifies the write path from ML pipelines.

6. **Tenant settings as JSONB** — deployment-specific configuration (compliance frameworks, session timeouts, posture check intervals) stored as JSONB on the tenants table. Each customer can have different settings without schema changes.

7. **GIN indexes on JSONB columns** — every JSONB column used in WHERE clauses has a GIN index, enabling efficient containment queries (`@>`) and key-existence checks (`?`). This is critical for policy evaluation performance.

8. **Connector linked_app_ids as UUID array** — connector-to-application mapping uses a PostgreSQL array column instead of a junction table, reducing join overhead for the hot path (connector routing).

9. **OCSF compatibility in audit events** — `event_data` JSONB on audit_events is structured to match OCSF event class schemas directly, enabling zero-transformation export to AWS Security Lake, Splunk, or any OCSF-compatible SIEM.

10. **Natural language preserved on policies** — the `metadata` JSONB on access_policies includes a `natural_language_source` field, recording the original prose that generated the policy rules via AI. This supports the AI-native policy authoring feature and provides audit evidence of policy intent.
