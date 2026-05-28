# Data Model Suggestion 4: Graph-Relational Hybrid

> Project: Zero Trust Network Access · Created: 2026-05-19

## Philosophy

This model adds a property graph layer on top of relational operational tables to handle the relationship-intensive queries that define zero trust security: "Can user X on device Y access application Z through connector C given policy P?" is fundamentally a graph traversal question. In a purely relational model, answering it requires joining 5-8 tables. In a graph model, it is a single path query. More importantly, ZTNA platforms need to answer second-order relationship questions that are expensive in relational models: "What is the blast radius if this device is compromised?" (all sessions, all applications, all other users who share those applications), "Is there a conflict of interest?" (user has both admin and auditor roles on the same application), and "What is the shortest trust path between this external contractor and the production database?"

The model uses PostgreSQL's `ltree` extension for hierarchical data (organizational units, network segments, compliance frameworks) and a generic graph edge table for arbitrary typed relationships between entities. The relational tables handle CRUD operations and foreign key integrity; the graph layer handles relationship queries, path analysis, and AI-driven trust chain analysis. This is not a full graph database (Neo4j/Neptune) — it is a PostgreSQL-native approach using recursive CTEs, ltree, and a typed edge table that can be queried with standard SQL while providing graph semantics.

This approach is inspired by how Google's BeyondCorp models trust relationships internally and how modern SIEM platforms (Splunk, Microsoft Sentinel) use entity graphs for threat investigation. The entity-relationship graph is also the natural substrate for the AI anomaly detection described in the project scope: behavioral baselines are patterns in the graph (user X normally accesses applications A, B, C from device D in location L), and anomalies are deviations from those graph patterns.

**Best for:** Platforms where relationship queries dominate (blast radius analysis, trust chain verification, conflict-of-interest detection, AI behavioral baselining from access patterns).

**Trade-offs:**
- (+) Relationship queries (blast radius, trust chains, path analysis) are natural and fast
- (+) AI behavioral analysis operates on graph patterns rather than flat table scans
- (+) Conflict-of-interest and separation-of-duty checks are graph queries
- (+) Entity-relationship visualization maps directly to the data model
- (+) Hierarchical data (org units, network segments) handled natively by ltree
- (-) Two-layer model (relational + graph) increases application complexity
- (-) Graph edge table can grow large with high-cardinality relationships
- (-) Developers must learn ltree and recursive CTE patterns
- (-) Not a true graph database — complex multi-hop traversals are slower than Neo4j
- (-) Edge table maintenance (creating/deleting edges when entities change) adds write overhead

---

## Standards Alignment

| Standard | How It's Used |
|----------|---------------|
| NIST SP 800-207 | Trust evaluation modeled as graph traversal from subject through PDP to resource |
| NIST SP 800-207A | Multi-cloud trust domains as graph partitions with cross-domain edges |
| CISA Zero Trust Maturity Model v2.0 | Five pillars modeled as graph node types with maturity edges |
| ISO/IEC 27001:2022 (A.8.20) | Network segmentation as ltree hierarchy with segment containment queries |
| BeyondCorp | Trust chain from user → device → network → application modeled as graph path |
| SPIFFE | Trust domain federation modeled as cross-domain graph edges |
| OAuth 2.0 / OIDC | Identity provider trust chains modeled as graph relationships |
| OCSF | Audit events enriched with graph context (actor node, resource node, path) |
| NIST CSF 2.0 | Protect/Detect functions mapped to graph-based access control and anomaly detection |

---

## Graph Layer

### graph_nodes

```sql
-- Enable ltree extension for hierarchical data
CREATE EXTENSION IF NOT EXISTS ltree;

-- Generic node table — every entity that participates in relationships
CREATE TABLE graph_nodes (
    node_id         UUID PRIMARY KEY,                  -- Same as the entity's PK in its relational table
    tenant_id       UUID NOT NULL,
    node_type       VARCHAR(50) NOT NULL CHECK (node_type IN (
        'user', 'group', 'device', 'application', 'connector',
        'network_segment', 'policy', 'org_unit', 'role',
        'workload_identity', 'idp', 'compliance_framework',
        'service_account', 'tenant'
    )),
    label           VARCHAR(255) NOT NULL,             -- Human-readable label for visualization
    hierarchy_path  LTREE,                             -- Hierarchical position (e.g., org.engineering.platform)
    properties      JSONB NOT NULL DEFAULT '{}',       -- Denormalized key attributes for graph queries
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_gn_tenant_type ON graph_nodes(tenant_id, node_type);
CREATE INDEX idx_gn_hierarchy ON graph_nodes USING GIST (hierarchy_path);
CREATE INDEX idx_gn_properties ON graph_nodes USING GIN (properties);
CREATE INDEX idx_gn_label ON graph_nodes(tenant_id, label);
```

### graph_edges

```sql
-- Typed, directed edges between nodes
CREATE TABLE graph_edges (
    edge_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    source_node_id  UUID NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
    target_node_id  UUID NOT NULL REFERENCES graph_nodes(node_id) ON DELETE CASCADE,
    edge_type       VARCHAR(50) NOT NULL CHECK (edge_type IN (
        -- Identity relationships
        'member_of',              -- user -> group
        'has_role',               -- user/group -> role
        'authenticated_by',       -- user -> idp
        'owns',                   -- user -> device

        -- Access relationships
        'can_access',             -- user/group/role -> application (derived from policy)
        'protected_by',           -- application -> policy
        'enforced_at',            -- policy -> application
        'serves',                 -- connector -> application
        'connects_to',            -- connector -> network_segment

        -- Organizational relationships
        'belongs_to',             -- user/device/app -> org_unit
        'child_of',               -- org_unit -> org_unit
        'reports_to',             -- user -> user (management chain)

        -- Network relationships
        'subnet_of',              -- network_segment -> network_segment
        'hosts',                  -- network_segment -> application
        'peers_with',             -- connector -> connector (mesh)

        -- Compliance relationships
        'compliant_with',         -- policy/application -> compliance_framework
        'audited_by',             -- application -> role (auditor role)

        -- Trust relationships
        'trusts',                 -- idp -> idp (federation)
        'attested_by',            -- workload_identity -> attestation source
        'delegates_to'            -- service_account -> workload_identity
    )),
    weight          REAL NOT NULL DEFAULT 1.0,         -- Edge weight for scoring/ranking
    properties      JSONB NOT NULL DEFAULT '{}',       -- Edge-specific metadata
    -- properties examples:
    -- member_of: {"added_at": "2026-01-15", "source": "scim"}
    -- can_access: {"via_policy": "uuid", "conditions": "business_hours_only"}
    -- has_role: {"scope": "tenant", "scope_id": null}
    -- serves: {"is_primary": true, "latency_ms": 12}
    valid_from      TIMESTAMPTZ NOT NULL DEFAULT now(),
    valid_until     TIMESTAMPTZ,                       -- NULL means currently valid; temporal edges
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ge_source ON graph_edges(source_node_id, edge_type) WHERE valid_until IS NULL;
CREATE INDEX idx_ge_target ON graph_edges(target_node_id, edge_type) WHERE valid_until IS NULL;
CREATE INDEX idx_ge_tenant_type ON graph_edges(tenant_id, edge_type);
CREATE INDEX idx_ge_temporal ON graph_edges(valid_from, valid_until);
CREATE UNIQUE INDEX idx_ge_unique_active ON graph_edges(source_node_id, target_node_id, edge_type)
    WHERE valid_until IS NULL;                         -- Prevent duplicate active edges
```

---

## Relational Operations Layer

### tenants

```sql
CREATE TABLE tenants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            VARCHAR(255) NOT NULL,
    slug            VARCHAR(100) NOT NULL UNIQUE,
    plan            VARCHAR(50) NOT NULL DEFAULT 'free',
    settings        JSONB NOT NULL DEFAULT '{}',
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
    provider_type   VARCHAR(50) NOT NULL,
    config          JSONB NOT NULL,
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
    credentials     JSONB NOT NULL DEFAULT '[]',
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_users_ext ON users(tenant_id, idp_id, external_id);
CREATE INDEX idx_users_email ON users(tenant_id, email);
```

### groups

```sql
CREATE TABLE groups (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    source          VARCHAR(50) NOT NULL DEFAULT 'local',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_groups_name ON groups(tenant_id, name);
```

### roles

```sql
CREATE TABLE roles (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(100) NOT NULL,
    description     TEXT,
    permissions     JSONB NOT NULL DEFAULT '[]',       -- ["policies:read", "policies:write", "sessions:read"]
    is_system       BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX idx_roles_name ON roles(tenant_id, name);
```

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
    latest_posture  JSONB NOT NULL DEFAULT '{}',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_devices_tenant ON devices(tenant_id);
CREATE INDEX idx_devices_user ON devices(user_id);
```

### applications

```sql
CREATE TABLE applications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    app_type        VARCHAR(50) NOT NULL,
    connection      JSONB NOT NULL,
    tags            JSONB NOT NULL DEFAULT '[]',
    is_active       BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_apps_tenant ON applications(tenant_id);
CREATE UNIQUE INDEX idx_apps_name ON applications(tenant_id, name);
```

### connectors

```sql
CREATE TABLE connectors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    status          VARCHAR(30) NOT NULL DEFAULT 'pending',
    config          JSONB NOT NULL DEFAULT '{}',
    last_heartbeat  TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_connectors_tenant ON connectors(tenant_id);
```

### access_policies

```sql
CREATE TABLE access_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    description     TEXT,
    action          VARCHAR(20) NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 100,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    rules           JSONB NOT NULL DEFAULT '[]',
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_policies_tenant ON access_policies(tenant_id, priority);
```

### network_segments

```sql
CREATE TABLE network_segments (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    cidr            CIDR NOT NULL,
    environment     VARCHAR(50),
    hierarchy_path  LTREE,                             -- e.g., 'network.us_east_1.prod.app_tier'
    cloud_info      JSONB NOT NULL DEFAULT '{}',       -- VPC, subnet, security group details
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_segments_tenant ON network_segments(tenant_id);
CREATE INDEX idx_segments_hierarchy ON network_segments USING GIST (hierarchy_path);
CREATE INDEX idx_segments_cidr ON network_segments USING GIST (cidr inet_ops);
```

### org_units

```sql
-- Organizational hierarchy (departments, teams, cost centers)
CREATE TABLE org_units (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id),
    name            VARCHAR(255) NOT NULL,
    hierarchy_path  LTREE NOT NULL,                    -- e.g., 'org.engineering.platform'
    parent_id       UUID REFERENCES org_units(id),
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_ou_tenant ON org_units(tenant_id);
CREATE INDEX idx_ou_hierarchy ON org_units USING GIST (hierarchy_path);
CREATE INDEX idx_ou_parent ON org_units(parent_id);
```

---

## Session & Audit Layer

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
    risk_score      SMALLINT NOT NULL DEFAULT 0,
    context         JSONB NOT NULL DEFAULT '{}',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_verified_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ended_at        TIMESTAMPTZ,
    termination_reason VARCHAR(50),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sessions_active ON access_sessions(tenant_id, status) WHERE status = 'active';
CREATE INDEX idx_sessions_user ON access_sessions(user_id, started_at DESC);
```

### audit_events

```sql
CREATE TABLE audit_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL,
    event_time      TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type      VARCHAR(100) NOT NULL,
    severity        SMALLINT NOT NULL DEFAULT 1,
    actor_node_id   UUID,                              -- Reference to graph_nodes for graph-enriched queries
    resource_node_id UUID,                             -- Reference to graph_nodes
    event_data      JSONB NOT NULL DEFAULT '{}',
    ocsf_class_uid  INTEGER,
    outcome         VARCHAR(20) NOT NULL
) PARTITION BY RANGE (event_time);

CREATE TABLE audit_events_2026_05 PARTITION OF audit_events
    FOR VALUES FROM ('2026-05-01') TO ('2026-06-01');

CREATE INDEX idx_audit_tenant_time ON audit_events(tenant_id, event_time DESC);
CREATE INDEX idx_audit_actor_node ON audit_events(actor_node_id, event_time DESC);
CREATE INDEX idx_audit_resource_node ON audit_events(resource_node_id, event_time DESC);
```

---

## Graph Query Examples

### Access path verification: Can user X access application Y?

```sql
-- Traverse: user -> member_of -> group -> can_access -> application
-- Also: user -> has_role -> role -> can_access -> application
WITH RECURSIVE access_paths AS (
    -- Start from the user node
    SELECT
        e.source_node_id,
        e.target_node_id,
        e.edge_type,
        ARRAY[e.source_node_id] AS path,
        1 AS depth
    FROM graph_edges e
    WHERE e.source_node_id = :user_id
      AND e.valid_until IS NULL
      AND e.edge_type IN ('member_of', 'has_role', 'can_access')

    UNION ALL

    -- Traverse outward
    SELECT
        e.source_node_id,
        e.target_node_id,
        e.edge_type,
        ap.path || e.target_node_id,
        ap.depth + 1
    FROM graph_edges e
    JOIN access_paths ap ON e.source_node_id = ap.target_node_id
    WHERE e.valid_until IS NULL
      AND e.edge_type IN ('member_of', 'has_role', 'can_access')
      AND ap.depth < 5                                -- Max traversal depth
      AND NOT (e.target_node_id = ANY(ap.path))       -- Prevent cycles
)
SELECT DISTINCT path
FROM access_paths
WHERE target_node_id = :application_id
  AND edge_type = 'can_access';
```

### Blast radius analysis: What is exposed if device X is compromised?

```sql
-- Find all entities reachable from a compromised device
WITH RECURSIVE blast_radius AS (
    -- Start from the device
    SELECT
        gn.node_id,
        gn.node_type,
        gn.label,
        0 AS hops,
        ARRAY[gn.node_id] AS path
    FROM graph_nodes gn
    WHERE gn.node_id = :device_id

    UNION ALL

    -- Traverse outward through active edges
    SELECT
        gn.node_id,
        gn.node_type,
        gn.label,
        br.hops + 1,
        br.path || gn.node_id
    FROM blast_radius br
    JOIN graph_edges e ON (
        e.source_node_id = br.node_id OR e.target_node_id = br.node_id
    )
    JOIN graph_nodes gn ON gn.node_id = CASE
        WHEN e.source_node_id = br.node_id THEN e.target_node_id
        ELSE e.source_node_id
    END
    WHERE e.valid_until IS NULL
      AND br.hops < 4                                 -- Max blast radius depth
      AND NOT (gn.node_id = ANY(br.path))
)
SELECT node_type, label, hops, path
FROM blast_radius
WHERE node_type IN ('application', 'user', 'network_segment')
ORDER BY hops ASC, node_type;
```

### Conflict of interest: Users with both admin and auditor roles on the same application

```sql
SELECT
    u.email,
    u.display_name,
    app.name AS application_name,
    admin_role.label AS admin_role,
    audit_role.label AS audit_role
FROM graph_edges admin_edge
JOIN graph_edges admin_access ON (
    admin_edge.target_node_id = admin_access.source_node_id
    AND admin_access.edge_type = 'can_access'
    AND admin_access.valid_until IS NULL
)
JOIN graph_edges audit_edge ON (
    admin_edge.source_node_id = audit_edge.source_node_id
    AND audit_edge.edge_type = 'has_role'
    AND audit_edge.valid_until IS NULL
)
JOIN graph_edges audit_access ON (
    audit_edge.target_node_id = audit_access.source_node_id
    AND audit_access.edge_type = 'audited_by'
    AND audit_access.valid_until IS NULL
    AND audit_access.source_node_id = admin_access.target_node_id  -- Same application
)
JOIN users u ON u.id = admin_edge.source_node_id
JOIN applications app ON app.id = admin_access.target_node_id
JOIN graph_nodes admin_role ON admin_role.node_id = admin_edge.target_node_id
JOIN graph_nodes audit_role ON audit_role.node_id = audit_edge.target_node_id
WHERE admin_edge.edge_type = 'has_role'
  AND admin_edge.valid_until IS NULL
  AND admin_role.properties->>'is_admin' = 'true';
```

### Network hierarchy: All applications in a specific network segment and its sub-segments

```sql
-- Using ltree: find all network segments under 'network.us_east_1.prod'
SELECT
    app.name AS application_name,
    app.app_type,
    ns.name AS segment_name,
    ns.cidr
FROM network_segments ns
JOIN graph_edges e ON e.source_node_id = ns.id AND e.edge_type = 'hosts' AND e.valid_until IS NULL
JOIN applications app ON app.id = e.target_node_id
WHERE ns.hierarchy_path <@ 'network.us_east_1.prod'   -- All descendants of prod
  AND ns.tenant_id = :tenant_id;
```

### Temporal graph: What did the access graph look like on a specific date?

```sql
-- Reconstruct the graph as it existed at a specific point in time
SELECT
    sn.label AS source_label,
    sn.node_type AS source_type,
    e.edge_type,
    tn.label AS target_label,
    tn.node_type AS target_type
FROM graph_edges e
JOIN graph_nodes sn ON sn.node_id = e.source_node_id
JOIN graph_nodes tn ON tn.node_id = e.target_node_id
WHERE e.tenant_id = :tenant_id
  AND e.valid_from <= '2026-05-15 03:00:00+00'
  AND (e.valid_until IS NULL OR e.valid_until > '2026-05-15 03:00:00+00')
ORDER BY e.edge_type, sn.label;
```

---

## Graph Maintenance

### Trigger: Sync graph when relational entities change

```sql
-- Example: when a user is added to a group, create a graph edge
CREATE OR REPLACE FUNCTION sync_group_membership_to_graph()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO graph_edges (tenant_id, source_node_id, target_node_id, edge_type, properties)
        SELECT u.tenant_id, NEW.user_id, NEW.group_id, 'member_of',
               jsonb_build_object('added_at', now(), 'source', 'group_membership')
        FROM users u WHERE u.id = NEW.user_id
        ON CONFLICT (source_node_id, target_node_id, edge_type)
            WHERE valid_until IS NULL DO NOTHING;
        RETURN NEW;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE graph_edges
        SET valid_until = now()
        WHERE source_node_id = OLD.user_id
          AND target_node_id = OLD.group_id
          AND edge_type = 'member_of'
          AND valid_until IS NULL;
        RETURN OLD;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_group_membership_graph
    AFTER INSERT OR DELETE ON group_members
    FOR EACH ROW EXECUTE FUNCTION sync_group_membership_to_graph();
```

### Derived edges: Recompute "can_access" edges from policies

```sql
-- Periodic job: recompute can_access edges from current policy state
-- This materializes the "who can access what" graph for fast traversal

-- Step 1: Expire all existing can_access edges
UPDATE graph_edges SET valid_until = now()
WHERE edge_type = 'can_access' AND valid_until IS NULL AND tenant_id = :tenant_id;

-- Step 2: Recompute from active policies
-- (Simplified; real implementation evaluates each policy rule)
INSERT INTO graph_edges (tenant_id, source_node_id, target_node_id, edge_type, weight, properties)
SELECT DISTINCT
    p.tenant_id,
    gm.user_id AS source_node_id,            -- User
    app_binding.target_node_id,               -- Application
    'can_access',
    1.0,
    jsonb_build_object('via_policy', p.id, 'policy_name', p.name, 'action', p.action)
FROM access_policies p
CROSS JOIN LATERAL jsonb_array_elements(p.rules) AS rule_elem
JOIN graph_edges group_binding ON (
    group_binding.edge_type = 'enforced_at'
    AND group_binding.source_node_id = p.id
    AND group_binding.valid_until IS NULL
) AS app_binding
-- ... (further rule evaluation joins)
WHERE p.tenant_id = :tenant_id
  AND p.is_active = true
  AND p.action = 'allow'
ON CONFLICT (source_node_id, target_node_id, edge_type)
    WHERE valid_until IS NULL DO NOTHING;
```

---

## Table Count Summary

| Category | Tables | Notes |
|----------|--------|-------|
| Graph Layer | 2 | graph_nodes, graph_edges (the core graph) |
| Identity | 5 | tenants, identity_providers, users, groups, roles |
| Device | 1 | devices (with JSONB posture) |
| Application & Network | 4 | applications, connectors, network_segments (ltree), org_units (ltree) |
| Policy | 1 | access_policies (JSONB rules) |
| Session & Audit | 2 | access_sessions, audit_events (partitioned) |
| **Total** | **15** | Plus partition tables; fewest tables of all models |

---

## Key Design Decisions

1. **Generic graph layer, not entity-specific edge tables** — a single `graph_edges` table with typed `edge_type` handles all relationships. This means new relationship types (e.g., "delegates_to" for workload identity delegation) can be added without schema changes. Trade-off: no type-specific column constraints on edge properties.

2. **Temporal edges with valid_from/valid_until** — every edge has a validity window. When a relationship changes, the old edge is expired (valid_until set) and a new edge created. This enables temporal graph queries ("who could access what on May 15th?") without maintaining a separate history table.

3. **ltree for hierarchical data** — network_segments and org_units use PostgreSQL's ltree extension for efficient ancestor/descendant queries. `<@` (is descendant of) and `@>` (is ancestor of) operators replace recursive CTEs for hierarchy queries.

4. **Graph node IDs match relational PKs** — graph_nodes.node_id is the same UUID as the entity's primary key in its relational table. No mapping table needed. Creating an entity in the relational table and inserting a graph node can be done in the same transaction.

5. **Derived "can_access" edges** — the most queried relationship (user → application access) is materialized as graph edges derived from policy evaluation. This pre-computes the expensive policy evaluation so that access path queries are fast. The edges are periodically recomputed when policies change.

6. **Blast radius as graph traversal** — the killer feature of this model. "If this device is compromised, what is the blast radius?" becomes a bounded BFS from the device node, collecting all reachable application and user nodes within N hops.

7. **Audit events reference graph nodes** — audit_events includes actor_node_id and resource_node_id, enabling graph-enriched audit queries: "show me all audit events involving nodes within 2 hops of this compromised device."

8. **Edge weight for trust scoring** — the `weight` field on edges enables trust chain scoring. A direct `has_role` edge with weight 1.0 represents stronger trust than an indirect path through 3 group memberships. The AI risk scoring engine sums edge weights to compute trust distance.

9. **Relational tables remain the CRUD source of truth** — the graph layer is a derived, query-optimized representation. Application code writes to relational tables; triggers and periodic jobs sync changes to the graph. If the graph becomes inconsistent, it can be rebuilt from relational data.

10. **PostgreSQL-native, no external graph DB** — the entire model runs on PostgreSQL with ltree and standard recursive CTEs. This avoids the operational complexity of a separate graph database (Neo4j, Neptune) while still providing graph semantics for the relationship queries that define ZTNA security analysis.
