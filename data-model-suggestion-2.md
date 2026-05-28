# Data Model Suggestion 2: Event-Sourced / Audit-First (CQRS)

> Project: Zero Trust Network Access · Created: 2026-05-19

## Philosophy

This model treats every state change in the ZTNA platform as an immutable event in an append-only event store. The event store is the single source of truth. Current state (active sessions, device posture, policy configuration) is derived by materializing read models from the event stream. This is a Command Query Responsibility Segregation (CQRS) architecture: write operations append events; read operations query projections that are rebuilt from those events.

The design is motivated by the core requirement of zero trust: continuous verification with full audit trail. In a traditional relational model, when a session's risk score changes, the old value is overwritten. In an event-sourced model, every risk score change is recorded as a distinct event, creating a complete temporal record that answers "what was the trust level at 14:32:07?" without any additional audit logging layer. The event store IS the audit log. This eliminates the dual-write problem where application state and audit logs can diverge.

This approach is inspired by how financial trading systems and healthcare platforms handle compliance — domains where regulators demand proof that every state transition was recorded, timestamped, and attributable to an actor. In the ZTNA context, it means every policy change, every posture assessment, every mid-session verification, and every access decision exists as an immutable event that can never be silently modified. Event replay enables temporal queries ("reconstruct all active sessions as of 3:00 AM during the incident"), forensic investigation, and AI training on the complete history of trust decisions.

**Best for:** Organisations with strict compliance requirements (FedRAMP, HIPAA, SOC 2) where full audit trail immutability is non-negotiable and temporal forensic queries are a core use case.

**Trade-offs:**
- (+) Complete immutable audit trail — every state change is recorded and attributable
- (+) Temporal queries native — "what was true at time T?" requires only event replay
- (+) No dual-write problem — the event store IS the audit log
- (+) AI/ML training data built-in — full behavioral history available for anomaly detection models
- (+) Natural fit for continuous verification — each re-evaluation is an event
- (-) Higher write amplification — every state change is an INSERT, never an UPDATE
- (-) Read model complexity — materialised views must be maintained and can lag
- (-) Schema evolution for events requires careful versioning (upcasting)
- (-) Eventual consistency between event store and read models
- (-) More complex application code — developers must think in events, not CRUD
- (-) Storage grows faster than mutable models (mitigated by snapshotting)

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| NIST SP 800-207 | Every PDP decision is an event; PEP enforcement is an event; PIP data retrieval is an event |
| NIST SP 800-207A | Multi-cloud events carry cloud_provider and region metadata |
| CISA Zero Trust Maturity Model v2.0 | Maturity progression tracked as events; pillar assessments are event-sourced |
| ISO/IEC 27001:2022 (A.8.20) | Network access events form the compliance evidence chain |
| OCSF | Event classification uses OCSF class_uid/activity_id for SIEM export |
| OAuth 2.0 / OIDC | Authentication events include IdP context and token lifecycle events |
| SPIFFE | Workload identity attestation events with SVID lifecycle |
| GDPR Article 32 | Immutable event log satisfies "appropriate technical measures" for access audit |

---

## Event Store (Source of Truth)

### event_streams

```sql
-- Tracks the aggregate roots (entities) that emit events
CREATE TABLE event_streams (
    stream_id       UUID PRIMARY KEY,
    stream_type     VARCHAR(50) NOT NULL CHECK (stream_type IN (
        'tenant', 'user', 'device', 'application', 'connector',
        'policy', 'session', 'workload_identity', 'service_account'
    )),
    tenant_id       UUID NOT NULL,
    current_version BIGINT NOT NULL DEFAULT 0,         -- Optimistic concurrency control
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_streams_tenant_type ON event_streams(tenant_id, stream_type);
```

### events

```sql
-- The append-only event store — the single source of truth
CREATE TABLE events (
    event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    stream_id       UUID NOT NULL REFERENCES event_streams(stream_id),
    stream_version  BIGINT NOT NULL,                   -- Monotonically increasing per stream
    event_type      VARCHAR(100) NOT NULL,             -- e.g., 'session.started', 'policy.rule_added'
    event_data      JSONB NOT NULL,                    -- Event payload (schema depends on event_type)
    metadata        JSONB NOT NULL DEFAULT '{}',       -- Actor, IP, correlation_id, causation_id
    ocsf_class_uid  INTEGER,                           -- OCSF classification for SIEM export
    ocsf_activity_id SMALLINT,
    tenant_id       UUID NOT NULL,                     -- Denormalized for partition pruning
    occurred_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    recorded_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (stream_id, stream_version)                 -- Optimistic concurrency guarantee
) PARTITION BY RANGE (occurred_at);

-- Monthly partitions
CREATE TABLE events_2026_05 PARTITION OF events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');
CREATE TABLE events_2026_06 PARTITION OF events
    FOR VALUES FROM ('2026-06-01') TO ('2026-07-01');

CREATE INDEX idx_events_stream ON events(stream_id, stream_version);
CREATE INDEX idx_events_tenant_type ON events(tenant_id, event_type, occurred_at DESC);
CREATE INDEX idx_events_type_time ON events(event_type, occurred_at DESC);
CREATE INDEX idx_events_ocsf ON events(ocsf_class_uid, occurred_at DESC) WHERE ocsf_class_uid IS NOT NULL;
```

### event_snapshots

```sql
-- Periodic snapshots to avoid replaying entire event history
CREATE TABLE event_snapshots (
    stream_id       UUID NOT NULL REFERENCES event_streams(stream_id),
    snapshot_version BIGINT NOT NULL,                  -- Stream version at snapshot time
    snapshot_data   JSONB NOT NULL,                    -- Full aggregate state at this version
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (stream_id, snapshot_version)
);
```

---

## Event Type Catalogue

Below are the primary event types with example `event_data` payloads. Each event is self-contained — it carries all data needed to reconstruct state without querying other tables.

### Identity Events

```sql
-- event_type: 'user.registered'
-- event_data example:
-- {
--   "user_id": "uuid",
--   "email": "user@example.com",
--   "display_name": "Jane Smith",
--   "idp_id": "uuid",
--   "external_id": "sub-claim-from-idp"
-- }

-- event_type: 'user.authenticated'
-- event_data example:
-- {
--   "user_id": "uuid",
--   "idp_id": "uuid",
--   "aal_level": 2,
--   "mfa_methods": ["fido2_webauthn"],
--   "ip_address": "203.0.113.42",
--   "geo_country": "US",
--   "user_agent": "Mozilla/5.0..."
-- }

-- event_type: 'user.credential_added'
-- event_data example:
-- {
--   "user_id": "uuid",
--   "credential_type": "fido2_webauthn",
--   "credential_ref": "public-key-hash",
--   "aal_level": 2
-- }

-- event_type: 'user.group_assigned'
-- event_data example:
-- {
--   "user_id": "uuid",
--   "group_id": "uuid",
--   "group_name": "engineering"
-- }
```

### Device Events

```sql
-- event_type: 'device.registered'
-- event_data example:
-- {
--   "device_id": "uuid",
--   "user_id": "uuid",
--   "device_name": "Jane's MacBook Pro",
--   "serial_number": "C02XX1234",
--   "os_type": "macos",
--   "os_version": "15.4",
--   "hardware_model": "MacBookPro18,1"
-- }

-- event_type: 'device.posture_assessed'
-- event_data example:
-- {
--   "device_id": "uuid",
--   "assessment_id": "uuid",
--   "os_version_compliant": true,
--   "disk_encrypted": true,
--   "firewall_enabled": true,
--   "antivirus_active": true,
--   "antivirus_up_to_date": true,
--   "screen_lock_enabled": true,
--   "jailbroken": false,
--   "overall_score": 95,
--   "overall_compliant": true,
--   "expires_at": "2026-05-19T16:00:00Z"
-- }

-- event_type: 'device.posture_failed'
-- event_data example:
-- {
--   "device_id": "uuid",
--   "failed_checks": ["antivirus_up_to_date", "os_version_compliant"],
--   "overall_score": 45,
--   "overall_compliant": false
-- }
```

### Policy Events

```sql
-- event_type: 'policy.created'
-- event_data example:
-- {
--   "policy_id": "uuid",
--   "name": "Engineering SSH Access",
--   "action": "allow",
--   "priority": 100,
--   "compliance_framework": "soc2"
-- }

-- event_type: 'policy.rule_added'
-- event_data example:
-- {
--   "policy_id": "uuid",
--   "rule_id": "uuid",
--   "rule_type": "identity_group",
--   "operator": "in",
--   "value": "engineering"
-- }

-- event_type: 'policy.bound_to_application'
-- event_data example:
-- {
--   "policy_id": "uuid",
--   "application_id": "uuid",
--   "application_name": "prod-ssh-bastion"
-- }

-- event_type: 'policy.ai_suggestion_generated'
-- event_data example:
-- {
--   "suggestion_id": "uuid",
--   "suggested_name": "Restrict contractor access to business hours",
--   "suggested_action": "allow",
--   "suggested_rules": [
--     {"rule_type": "identity_group", "operator": "equals", "value": "contractors"},
--     {"rule_type": "time_window", "operator": "in", "value": "09:00-17:00/Mon-Fri"}
--   ],
--   "confidence": 0.87,
--   "based_on_sessions": 1247
-- }
```

### Session Events

```sql
-- event_type: 'session.access_requested'
-- event_data example:
-- {
--   "session_id": "uuid",
--   "user_id": "uuid",
--   "device_id": "uuid",
--   "application_id": "uuid",
--   "ip_address": "203.0.113.42",
--   "geo_country": "US",
--   "geo_city": "San Francisco"
-- }

-- event_type: 'session.access_granted'
-- event_data example:
-- {
--   "session_id": "uuid",
--   "matched_policy_id": "uuid",
--   "risk_score": 12,
--   "posture_score": 95,
--   "aal_level": 2,
--   "connector_id": "uuid",
--   "evaluation_ms": 23
-- }

-- event_type: 'session.access_denied'
-- event_data example:
-- {
--   "session_id": "uuid",
--   "denial_reason": "device_posture_non_compliant",
--   "evaluated_policies": ["uuid1", "uuid2"],
--   "risk_score": 78,
--   "posture_score": 35
-- }

-- event_type: 'session.verified'
-- event_data example:
-- {
--   "session_id": "uuid",
--   "risk_score": 15,
--   "posture_score": 95,
--   "ip_changed": false,
--   "geo_changed": false,
--   "result": "pass"
-- }

-- event_type: 'session.risk_elevated'
-- event_data example:
-- {
--   "session_id": "uuid",
--   "previous_risk_score": 15,
--   "new_risk_score": 72,
--   "trigger": "geo_changed",
--   "action_taken": "mfa_prompted"
-- }

-- event_type: 'session.quarantined'
-- event_data example:
-- {
--   "session_id": "uuid",
--   "reason": "impossible_travel_detected",
--   "anomaly_detection_id": "uuid",
--   "escalated_to": "soc_analyst"
-- }

-- event_type: 'session.terminated'
-- event_data example:
-- {
--   "session_id": "uuid",
--   "reason": "user_logout",
--   "duration_seconds": 3847,
--   "total_verifications": 12,
--   "peak_risk_score": 23
-- }
```

### Connector Events

```sql
-- event_type: 'connector.registered'
-- event_type: 'connector.heartbeat'
-- event_type: 'connector.status_changed'
-- event_type: 'connector.application_linked'
-- event_type: 'connector.decommissioned'
```

---

## Materialised Read Models (Projections)

These tables are rebuilt from the event stream. They can be dropped and reconstructed at any time. They exist solely for query performance.

### rm_active_sessions

```sql
-- Read model: currently active sessions (rebuilt from session events)
CREATE TABLE rm_active_sessions (
    session_id      UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    user_id         UUID NOT NULL,
    device_id       UUID NOT NULL,
    application_id  UUID NOT NULL,
    connector_id    UUID,
    policy_id       UUID NOT NULL,
    status          VARCHAR(30) NOT NULL,
    risk_score      SMALLINT NOT NULL,
    posture_score   SMALLINT,
    ip_address      INET NOT NULL,
    geo_country     CHAR(2),
    started_at      TIMESTAMPTZ NOT NULL,
    last_verified_at TIMESTAMPTZ NOT NULL,
    verification_count INTEGER NOT NULL DEFAULT 0,
    last_projected_event UUID NOT NULL                 -- Event that last updated this row
);

CREATE INDEX idx_rm_sessions_tenant ON rm_active_sessions(tenant_id, status);
CREATE INDEX idx_rm_sessions_user ON rm_active_sessions(user_id);
CREATE INDEX idx_rm_sessions_risk ON rm_active_sessions(tenant_id, risk_score DESC) WHERE status = 'active';
```

### rm_current_devices

```sql
-- Read model: current device state and latest posture
CREATE TABLE rm_current_devices (
    device_id       UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    user_id         UUID,
    device_name     VARCHAR(255),
    serial_number   VARCHAR(255),
    os_type         VARCHAR(50) NOT NULL,
    os_version      VARCHAR(100),
    mdm_enrolled    BOOLEAN NOT NULL DEFAULT false,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    -- Latest posture (denormalized from most recent posture_assessed event)
    posture_score   SMALLINT,
    posture_compliant BOOLEAN,
    posture_assessed_at TIMESTAMPTZ,
    posture_expires_at TIMESTAMPTZ,
    first_seen_at   TIMESTAMPTZ NOT NULL,
    last_seen_at    TIMESTAMPTZ,
    last_projected_event UUID NOT NULL
);

CREATE INDEX idx_rm_devices_tenant ON rm_current_devices(tenant_id);
CREATE INDEX idx_rm_devices_user ON rm_current_devices(user_id);
```

### rm_current_policies

```sql
-- Read model: current policy configuration
CREATE TABLE rm_current_policies (
    policy_id       UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    action          VARCHAR(20) NOT NULL,
    priority        INTEGER NOT NULL,
    is_active       BOOLEAN NOT NULL,
    compliance_framework VARCHAR(50),
    rules           JSONB NOT NULL DEFAULT '[]',       -- Denormalized array of {rule_type, operator, value}
    bound_applications UUID[] NOT NULL DEFAULT '{}',   -- Array of application IDs
    version         BIGINT NOT NULL,                   -- Stream version this projection reflects
    last_projected_event UUID NOT NULL
);

CREATE INDEX idx_rm_policies_tenant ON rm_current_policies(tenant_id);
CREATE INDEX idx_rm_policies_priority ON rm_current_policies(tenant_id, priority);
```

### rm_current_users

```sql
-- Read model: current user state with group memberships
CREATE TABLE rm_current_users (
    user_id         UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    email           VARCHAR(320),
    display_name    VARCHAR(255),
    idp_id          UUID NOT NULL,
    external_id     VARCHAR(255) NOT NULL,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    groups          JSONB NOT NULL DEFAULT '[]',        -- [{group_id, group_name}]
    roles           JSONB NOT NULL DEFAULT '[]',        -- [{role_id, role_name, scope}]
    credentials_count INTEGER NOT NULL DEFAULT 0,
    max_aal_level   SMALLINT NOT NULL DEFAULT 1,
    last_login_at   TIMESTAMPTZ,
    last_projected_event UUID NOT NULL
);

CREATE INDEX idx_rm_users_tenant ON rm_current_users(tenant_id);
CREATE INDEX idx_rm_users_email ON rm_current_users(tenant_id, email);
```

### rm_connector_status

```sql
-- Read model: connector fleet status
CREATE TABLE rm_connector_status (
    connector_id    UUID PRIMARY KEY,
    tenant_id       UUID NOT NULL,
    name            VARCHAR(255) NOT NULL,
    status          VARCHAR(30) NOT NULL,
    version         VARCHAR(50),
    cloud_provider  VARCHAR(50),
    region          VARCHAR(100),
    ip_address      INET,
    linked_applications UUID[] NOT NULL DEFAULT '{}',
    last_heartbeat  TIMESTAMPTZ,
    last_projected_event UUID NOT NULL
);

CREATE INDEX idx_rm_connectors_tenant ON rm_connector_status(tenant_id, status);
```

### rm_risk_dashboard

```sql
-- Read model: pre-computed risk metrics per tenant (updated by projection)
CREATE TABLE rm_risk_dashboard (
    tenant_id       UUID PRIMARY KEY,
    active_sessions INTEGER NOT NULL DEFAULT 0,
    high_risk_sessions INTEGER NOT NULL DEFAULT 0,     -- risk_score > 70
    non_compliant_devices INTEGER NOT NULL DEFAULT 0,
    failed_access_last_hour INTEGER NOT NULL DEFAULT 0,
    anomalies_last_24h INTEGER NOT NULL DEFAULT 0,
    connectors_online INTEGER NOT NULL DEFAULT 0,
    connectors_offline INTEGER NOT NULL DEFAULT 0,
    last_updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

---

## Temporal Query Examples

### Reconstruct session state at a specific point in time

```sql
-- "What was the risk score of session X at 14:32:07?"
SELECT event_type, event_data, occurred_at
FROM events
WHERE stream_id = (SELECT stream_id FROM event_streams WHERE stream_id = :session_id)
  AND occurred_at <= '2026-05-19 14:32:07+00'
ORDER BY stream_version ASC;

-- Application code replays these events to reconstruct the session aggregate
-- at exactly that moment.
```

### Find all policy changes in the last 30 days

```sql
-- Full policy change history with actor attribution
SELECT
    e.event_type,
    e.event_data->>'policy_id' AS policy_id,
    e.event_data->>'name' AS policy_name,
    e.metadata->>'actor_id' AS changed_by,
    e.metadata->>'ip_address' AS from_ip,
    e.occurred_at
FROM events e
WHERE e.tenant_id = :tenant_id
  AND e.event_type LIKE 'policy.%'
  AND e.occurred_at >= now() - INTERVAL '30 days'
ORDER BY e.occurred_at DESC;
```

### Incident forensics: reconstruct all events during a time window

```sql
-- "Show me everything that happened between 03:00 and 03:15 during the incident"
SELECT
    e.event_type,
    e.stream_id,
    es.stream_type,
    e.event_data,
    e.metadata,
    e.occurred_at
FROM events e
JOIN event_streams es ON e.stream_id = es.stream_id
WHERE e.tenant_id = :tenant_id
  AND e.occurred_at BETWEEN '2026-05-15 03:00:00+00' AND '2026-05-15 03:15:00+00'
ORDER BY e.occurred_at ASC;
```

### AI training: extract behavioral patterns for a user

```sql
-- Complete access history for behavioral baselining
SELECT
    e.event_data->>'application_id' AS app_id,
    e.event_data->>'ip_address' AS ip,
    e.event_data->>'geo_country' AS country,
    e.occurred_at,
    extract(hour from e.occurred_at) AS hour_of_day,
    extract(dow from e.occurred_at) AS day_of_week
FROM events e
WHERE e.event_type = 'session.access_granted'
  AND e.event_data->>'user_id' = :user_id
  AND e.occurred_at >= now() - INTERVAL '90 days'
ORDER BY e.occurred_at ASC;
```

---

## Projection Rebuild Process

```sql
-- Example: rebuild rm_active_sessions from event store
-- This would typically be application code, but the SQL pattern:

TRUNCATE rm_active_sessions;

-- Replay all session events in order
WITH session_events AS (
    SELECT
        e.event_type,
        e.event_data,
        e.event_id,
        e.occurred_at,
        ROW_NUMBER() OVER (
            PARTITION BY e.event_data->>'session_id'
            ORDER BY e.stream_version ASC
        ) AS event_order
    FROM events e
    WHERE e.event_type LIKE 'session.%'
      AND e.tenant_id = :tenant_id
)
-- Application code iterates through these events applying state transitions:
-- session.access_granted  -> INSERT into rm_active_sessions
-- session.verified        -> UPDATE risk_score, last_verified_at
-- session.risk_elevated   -> UPDATE risk_score
-- session.quarantined     -> UPDATE status = 'quarantined'
-- session.terminated      -> DELETE from rm_active_sessions
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Event Store (Source of Truth) | 3 | event_streams, events (partitioned), event_snapshots |
| Read Models (Projections) | 6 | rm_active_sessions, rm_current_devices, rm_current_policies, rm_current_users, rm_connector_status, rm_risk_dashboard |
| **Total** | **9** | Plus monthly partition tables for events |

---

## Key Design Decisions

1. **Single event table, partitioned by time** — all event types share one table (`events`) with JSONB payloads. This simplifies the write path (one INSERT target) and enables cross-entity temporal queries. Monthly partitions allow retention management by dropping old partitions.

2. **Stream-per-aggregate** — each entity instance (a specific session, a specific device, a specific policy) has its own event_stream with a monotonically increasing version number. The UNIQUE constraint on (stream_id, stream_version) provides optimistic concurrency control without distributed locks.

3. **Snapshots every N events** — event_snapshots stores periodic aggregate state to avoid replaying thousands of events. A session with 500 verification events only needs to replay from the last snapshot (e.g., every 50 events).

4. **Read models are disposable** — every `rm_*` table can be dropped and rebuilt from the event store. This means projection bugs are fixable without data loss, and new projections can be added retroactively.

5. **OCSF classification on events** — optional `ocsf_class_uid` and `ocsf_activity_id` on each event enables direct streaming to SIEM platforms (AWS Security Lake, Splunk) without transformation.

6. **Metadata envelope** — every event carries a `metadata` JSONB field with actor_id, ip_address, correlation_id, and causation_id. The correlation_id links events from the same user request; causation_id records which event triggered this one (e.g., a posture failure event caused a session quarantine event).

7. **Dramatically fewer tables** — only 9 tables compared to ~30 in the normalized model. Complexity shifts from schema to application logic (event handlers and projection builders).

8. **Natural audit compliance** — the event store itself satisfies SOC 2, HIPAA, and FedRAMP audit trail requirements. There is no separate audit_events table because every event IS an audit event. Immutability is enforced by never issuing UPDATE or DELETE on the events table.

9. **Event versioning strategy** — when event schemas evolve (e.g., adding a new field to `session.verified`), old events retain their original structure. Application code uses "upcasters" to transform old event versions to the current schema during replay.

10. **Eventual consistency trade-off** — read models may lag behind the event store by milliseconds to seconds. For the PDP (which must decide access in real-time), the decision is made from the event store directly (or a strongly consistent projection), not from eventually consistent read models.
