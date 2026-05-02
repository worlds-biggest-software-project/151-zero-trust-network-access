# Zero Trust Network Access — Feature & Functionality Survey

> Candidate #151 · Researched: 2026-05-03

## Solutions Analysed

| Tool | Type | Licence / Model | URL |
|------|------|-----------------|-----|
| Zscaler Private Access (ZPA) | Commercial SaaS ZTNA | Per-user subscription; enterprise quotes | https://www.zscaler.com/products-and-solutions/zscaler-private-access |
| Palo Alto Prisma Access (ZTNA 2.0) | Commercial SaaS ZTNA | Per-seat enterprise licensing | https://www.paloaltonetworks.com/prisma/access |
| Cloudflare Access | Commercial SaaS ZTNA | Free tier up to 50 users; Teams ~$7/user/month | https://www.cloudflare.com/sase/products/access/ |
| Cisco Duo + ZTNA | Commercial SaaS Identity/Access Control | Per-user; bundled pricing | https://www.cisco.com/c/en_us/products/security/duo.html |
| Microsoft Entra Private Access | Commercial SaaS ZTNA | Bundled with Entra Suite or M365 E5 | https://learn.microsoft.com/en-us/entra/identity/zero-trust-access/ |
| Teleport | Open Source + Commercial | Free OSS (Apache 2.0); Enterprise SaaS | https://goteleport.com/ |
| Boundary (HashiCorp) | Open Source + Commercial | Free OSS; HCP Boundary enterprise SaaS | https://www.boundaryproject.io/ |
| Netskope Private Access | Commercial SaaS ZTNA | Per-user enterprise quotes; SSE bundle | https://www.netskope.com/products/netskope-private-access |
| Cato Networks | Commercial SaaS SD-WAN + ZTNA (SASE) | Per-user/site enterprise quotes | https://www.catonetworks.com/ |
| OpenZiti | Open Source Zero Trust Networking | Free (Apache 2.0); NetFoundry commercial support | https://openziti.io/ |

## Feature Analysis by Solution

### Zscaler Private Access (ZPA)

**Core features**
- Cloud-delivered ZTNA with continuous trust verification for every access request
- Context-aware validation: user identity, device posture, location, and application risk
- App Connectors deployed in private data centre, cloud (AWS, Azure, GCP), or on-prem networks with outbound-only connections
- No inbound firewall rules required; applications never exposed to internet
- Zero Trust Exchange: centralized policy and enforcement architecture
- Policy engine with granular access controls based on user, device, content, and application risk
- Supports diverse authentication and device posture validation
- Integration with Zscaler Security Service Edge (SSE) platform

**Differentiating features**
- World's most deployed ZTNA platform (massive scale and proven architecture)
- Outbound-only connector model (zero network exposure)
- Continuous context validation beyond initial authentication
- Native integration with broader Zscaler SSE ecosystem

**UX patterns**
- Light weight App Connector deployment (minimal overhead)
- Continuous policy evaluation on every request
- Context-based decision points (user + device + location + app)
- Centralized policy management across all private applications

**Integration points**
- Cloud providers (AWS, Azure, GCP)
- Identity providers (OAuth 2.0 / OIDC)
- Device management platforms
- SIEM and logging integrations
- Zscaler SSE platform integration

**Known gaps**
- Expensive for SMEs compared to Cloudflare ($20–60/user/month enterprise pricing)
- Cloud-only SaaS model creates vendor lock-in
- Requires connector deployment overhead vs. purely agentless solutions

**Licence / IP notes**
- Proprietary commercial Zscaler licence
- No known patent encumbrances identified

---

### Palo Alto Prisma Access (ZTNA 2.0)

**Core features**
- Identity-based, application-specific access control
- Continuous trust verification at access time and mid-session
- Deep packet inspection for traffic visibility
- ZTNA 2.0: advanced continuous verification features
- Broad platform integration: Prisma Cloud (CSPM), threat intelligence, logging
- Application-specific policies with granular enforcement
- Device posture and compliance evaluation
- Multi-cloud support across AWS, Azure, GCP, OCI
- Integration with Palo Alto Networks security fabric

**Differentiating features**
- Continuous trust verification (not just initial auth)
- Deep inspection capabilities for application-layer security
- Tight integration with Prisma Cloud CSPM for context
- ZTNA 2.0 evolution adds mid-session verification

**UX patterns**
- Application-centric policy definition (not network-centric)
- Continuous verification workflow (periodic re-authentication/posture checks)
- Integration with threat intelligence for risk context
- Centralized policy management across diverse apps

**Integration points**
- Prisma Cloud CSPM and threat intelligence
- Cloud provider APIs
- Identity providers (SAML, OAuth 2.0)
- Device management platforms
- Logging and SIEM platforms

**Known gaps**
- Complex configuration reported in user reviews
- High enterprise pricing with custom quotes
- Steep learning curve for teams new to continuous verification

**Licence / IP notes**
- Proprietary Palo Alto Networks licence
- No known patent encumbrances identified

---

### Cloudflare Access

**Core features**
- Identity-first zero trust access to internal applications and resources
- Granular identity- and context-based access policies
- User identity verification via configured identity provider
- Device posture checking before granting access
- Multi-factor authentication (MFA) enforcement
- Support for SSH, RDP, and web applications
- Global edge network deployment (low latency)
- Free tier up to 50 users; generous free-tier feature set
- Teams plan: ~$7/user/month
- Quantum-safe encryption and access

**Differentiating features**
- Lowest cost entry point ($7/user/month vs. $20–60 for enterprise competitors)
- Free tier with substantial features (major barrier removal for SMEs)
- Fast global edge network (Cloudflare's existing infrastructure)
- Straightforward onboarding compared to enterprise ZTNA platforms
- Quantum-safe encryption positioning

**UX patterns**
- Identity provider-first (authenticate via configured IdP)
- Device posture evaluation at login
- Granular policy definition based on user/group attributes
- Web-based policy management UI

**Integration points**
- Identity providers (SSO, SAML, OAuth 2.0, OIDC)
- Device management platforms
- Slack, GitHub, Google Workspace integrations
- Audit logging and reporting

**Known gaps**
- Less mature for complex enterprise routing requirements
- Limited deep packet inspection capabilities vs. Palo Alto/Zscaler
- Setup complexity increases with wide infrastructure

**Licence / IP notes**
- Proprietary Cloudflare commercial licence
- No known patent encumbrances identified

---

### Cisco Duo + ZTNA

**Core features**
- Identity-centric access control integrated with Cisco security stack
- Duo multi-factor authentication (MFA) as foundation
- ZTNA capabilities layered on identity and device verification
- Device health assessment and posture validation
- Support for diverse applications and protocols
- Integration with Cisco networking products
- Compliance reporting and audit logging

**Differentiating features**
- Deep Cisco ecosystem integration (Meraki, SD-WAN, ISE)
- Proven Duo MFA platform as security backbone
- Bundled pricing options across Cisco product lines

**UX patterns**
- Identity verification (via Duo) before access
- Device health checks (posture evaluation)
- Centralized policy management
- Cisco Admin Portal for configuration

**Integration points**
- Cisco Meraki (networking)
- Cisco DNA (device management)
- Cisco ISE (identity services)
- Identity providers (Active Directory, Okta, etc.)
- SIEM and logging platforms

**Known gaps**
- Fragmented across multiple Cisco product lines (ZTNA not unified in single offering)
- Requires significant Cisco stack investment for optimal value
- Less accessible for non-Cisco environments

**Licence / IP notes**
- Proprietary Cisco commercial licence
- No known patent encumbrances identified

---

### Microsoft Entra Private Access

**Core features**
- ZTNA capabilities integrated into Microsoft Entra (formerly Azure AD) identity platform
- Identity-based access control for private applications and infrastructure
- Device-conditional access policies (device compliance, location, risk)
- Seamless integration with Microsoft 365 and Azure environments
- Bundled licensing with Entra Suite or Microsoft 365 E5
- Multi-factor authentication (MFA) integration
- Compliance and audit logging

**Differentiating features**
- Seamless Microsoft 365 and Azure integration (no separate tool)
- Conditional Access policies tied to device and risk context
- Cost efficiency for Microsoft-centric organisations (bundled with M365 E5)
- Native Active Directory integration

**UX patterns**
- Identity-first authentication (via Entra)
- Conditional access rules (device compliance, location, risk signals)
- Azure Portal for policy management
- Deep M365 ecosystem integration

**Integration points**
- Microsoft Entra (identity)
- Microsoft 365 (bundled)
- Azure resources and applications
- Active Directory (on-prem)
- Conditional Access engine
- Device management (Intune)

**Known gaps**
- Limited to Microsoft-centric environments; weak for non-Microsoft apps
- Less granular policy control vs. dedicated ZTNA platforms
- Requires M365 E5 licensing (expensive for ZTNA-only use case)

**Licence / IP notes**
- Proprietary Microsoft commercial licence
- No known patent encumbrances identified

---

### Teleport

**Core features**
- Open-source infrastructure access platform with ZTNA capabilities
- Certificate-based access (no shared secrets or passwords)
- SSH, Kubernetes, and application access in single platform
- Session recording and audit logging
- Identity verification via OIDC/SAML
- Role-based access control (RBAC)
- Database access with proxy
- Web application access
- Enterprise SaaS option (Teleport Cloud)
- Apache 2.0 open source licence

**Differentiating features**
- Developer-friendly, certificate-based security model
- Infrastructure-focused (SSH, K8s primacy over general applications)
- Open-source core with enterprise SaaS option
- Session recording and forensics capabilities
- Unified access for infra, K8s, and web apps

**UX patterns**
- Certificate-based authentication (no key sharing)
- OIDC/SAML integration for identity
- RBAC policies (role-based, not user-based)
- CLI-first access patterns (developer-centric)
- Session recording for audit

**Integration points**
- Kubernetes APIs
- SSH infrastructure
- AWS EC2, GCP, Azure compute
- OIDC/SAML identity providers
- Audit logging and SIEM
- Terraform for IaC deployment

**Known gaps**
- Primarily focused on infrastructure (SSH, K8s); less polished for general web applications
- Open-source deployment requires operational expertise
- Enterprise pricing not publicly disclosed
- Smaller ecosystem vs. commercial ZTNA leaders

**Licence / IP notes**
- Apache 2.0 open-source licence (free, modifiable, distributable)
- Commercial enterprise support available from Teleport Inc.
- No licence conflicts identified

---

### Boundary (HashiCorp)

**Core features**
- Identity-based access management for dynamic infrastructure
- Integration with HashiCorp Vault and Terraform ecosystem
- Support for SSH, RDP, databases, Kubernetes, cloud resources
- Policy-driven access decisions
- Session recording and audit
- Dynamic credential generation (integration with Vault)
- Multi-cloud support (AWS, Azure, GCP, on-prem)
- Apache 2.0 open source; HCP Boundary enterprise SaaS
- Credential management via Vault integration

**Differentiating features**
- Tight HashiCorp ecosystem integration (Terraform, Vault, Consul)
- Dynamic credential generation (Vault integration)
- Infrastructure-focused design (IaC-native)
- Identity-based policies without static roles

**UX patterns**
- Terraform-defined access policies (IaC-first)
- Vault-generated credentials (dynamic, short-lived)
- Policy decision points based on identity and resource attributes
- Session recording for compliance

**Integration points**
- HashiCorp Vault (credential management)
- Terraform (infrastructure definition)
- Kubernetes APIs
- Cloud providers (AWS, Azure, GCP)
- Identity providers (OIDC, SAML)
- SSH, RDP, databases

**Known gaps**
- Requires significant HashiCorp stack investment (Vault + Terraform knowledge)
- Less mature for non-IaC workflows
- HCP Boundary enterprise pricing not publicly available
- Smaller ecosystem than commercial ZTNA leaders

**Licence / IP notes**
- Business Source Licence (BSL) for open source; commercial licence for HCP Boundary
- BSL transitions to Apache 2.0 after ~4 years
- No licence conflicts identified for standard use

---

### Netskope Private Access

**Core features**
- ZTNA module within Netskope's Security Service Edge (SSE) platform
- Identity and device-based access control
- Integration with Netskope CASB (Cloud Access Security Broker)
- DLP (Data Loss Prevention) integration for application-layer security
- Network tunnel over Netskope infrastructure
- Compliance and audit logging
- Enterprise per-user SaaS subscription
- Dashboard and policy management

**Differentiating features**
- Strong integration with Netskope DLP and CASB capabilities
- Application-aware network tunnel (not just access gate)
- SSE platform convergence (networking + security)
- Data protection layer in ZTNA architecture

**UX patterns**
- Identity verification before access
- Device posture checking
- DLP policy enforcement at application layer
- Centralized policy management across ZTNA + DLP + CASB

**Integration points**
- Netskope DLP and CASB
- Netskope SSE platform
- Identity providers (SAML, OAuth 2.0)
- Device management platforms
- Cloud and on-prem applications

**Known gaps**
- Pricing opacity (custom enterprise quotes only)
- Best value within Netskope SSE ecosystem (requires DLP/CASB adoption)
- Less feature-rich for simpler use cases

**Licence / IP notes**
- Proprietary Netskope commercial licence
- No known patent encumbrances identified

---

### Cato Networks

**Core features**
- Converged SD-WAN + ZTNA platform (SASE architecture)
- Identity-based access control
- Unified networking and security (no separate tools)
- Cloud-native backbone with global data centres
- Application-specific routing and policies
- Device posture and compliance evaluation
- Threat prevention and DLP integration
- Multi-cloud and hybrid network support
- Enterprise per-user/site SaaS pricing

**Differentiating features**
- Unified SD-WAN + ZTNA convergence (one platform for networking and access)
- Simplified deployment vs. separate tools
- Cloud-native backbone with global edge
- Integrated threat prevention

**UX patterns**
- SD-WAN appliance deployment or cloud gateway
- Identity-based policy authoring (role/group-based)
- Application routing policies (QoS + security)
- Centralized management console

**Integration points**
- Cloud providers (AWS, Azure, GCP)
- Identity providers
- Device management
- Threat intelligence feeds
- On-prem networks (via gateway)
- Branches and remote sites

**Known gaps**
- Less granular access policy control vs. dedicated ZTNA platforms
- Networking-first positioning may overshadow ZTNA capabilities for security teams
- Enterprise custom quotes (pricing opacity)

**Licence / IP notes**
- Proprietary Cato commercial licence
- No known patent encumbrances identified

---

### OpenZiti

**Core features**
- Open-source zero trust networking framework with embedded ZTNA
- Embeddable in applications (lightweight SDK)
- Identity-centric access model
- No centralized gateway required (distribu​ted architecture)
- Support for diverse protocols and applications
- Certificate-based authentication
- Audit logging and policy enforcement
- Apache 2.0 open source licence
- NetFoundry provides commercial support and cloud hosting

**Differentiating features**
- Truly open source (Apache 2.0; no proprietary fork)
- Embeddable in applications (very lightweight)
- No centralized gateway bottleneck (distributed overlay network)
- Identity-first from the ground up

**UX patterns**
- SDK integration into applications
- Certificate-based authentication
- Policy-driven access decisions
- Lightweight agent/connector model

**Integration points**
- Applications (via SDK)
- Identity providers (OIDC, SAML)
- Certificate infrastructure (PKI)
- NetFoundry cloud platform (optional commercial)
- Monitoring and logging systems

**Known gaps**
- Steep learning curve for operators and developers
- Immature ecosystem (fewer integrations vs. commercial platforms)
- NetFoundry commercial offering less visible than pure open source
- Limited vendor support compared to commercial alternatives

**Licence / IP notes**
- Apache 2.0 open-source licence (free, modifiable, distributable)
- NetFoundry provides commercial support and SaaS hosting
- No licence conflicts identified

---

## Cross-Cutting Feature Themes

### Table-Stakes Features

Any ZTNA platform in this category must provide:

- **Identity verification** for every access attempt (via identity provider integration)
- **Device posture evaluation** checking device health, compliance, and risk before granting access
- **Granular access policies** allowing definition of fine-grained access rules based on user, device, application, and context
- **Continuous verification** re-evaluating trust mid-session, not just at initial login
- **Support for multiple application types**: web apps, SSH, RDP, databases, APIs, Kubernetes
- **Audit logging and session recording** for compliance and forensics
- **Multi-factor authentication (MFA)** support or enforcement
- **Compliance reporting** for regulatory frameworks (SOC 2, HIPAA, FedRAMP, PCI-DSS)
- **Role-based access control (RBAC)** or attribute-based access control (ABAC)

### Differentiating Features

Capabilities that separate leading solutions from commoditised competitors:

- **Continuous context-aware verification** — re-evaluating risk mid-session based on behavior, location, device drift without re-auth (Zscaler ZPA, Palo Alto ZTNA 2.0, Mimecast)
- **Application-aware networking** — routing decisions based on application and user context, not just network layer (Cato, Netskope)
- **Outbound-only connector model** — applications never exposed to internet, zero inbound rules required (Zscaler ZPA)
- **Low-latency global edge** — geographically distributed points of presence for fast access anywhere (Cloudflare Access, Cato)
- **Bundled ecosystem** — ZTNA converged with CSPM, DLP, CASB, threat prevention in one platform (Palo Alto, Netskope, Cato)
- **Open-source option with commercial support** — free OSS core with optional enterprise SaaS (Teleport, Boundary, OpenZiti)
- **Certificate-based authentication** — modern zero-trust credential model vs. username/password (Teleport, OpenZiti, Boundary)
- **Kubernetes-native access** — deep K8s integration for workload identity and service-to-service zero trust (Teleport, Boundary, Palo Alto)
- **Embedded SDK** — lightweight zero-trust integration directly into applications (OpenZiti)
- **Deep DLP integration** — data protection layer within access control (Netskope, Cato)
- **Affordable SME pricing** — low per-user cost with free or freemium tier (Cloudflare $7/user/month, free tier up to 50)

### Underserved Areas / Opportunities

Gaps in the market where a new entrant or existing player could add differentiated value:

- **AI-driven policy generation** — Most platforms require manual policy authoring; no platform yet auto-generates policies from observed access patterns.
- **Natural-language policy authoring** — No platform yet translates "Allow contractors to access the billing app 9–5 weekdays" into enforcement rules.
- **Predictive anomaly detection** — Continuous behavioral baselining to detect access anomalies in real time (partial implementations exist; maturity gap).
- **Automated remediation** — Upon detecting compromise signals (unusual location, device drift, behaviour anomaly), auto-quarantine sessions or escalate (none fully operational).
- **SME affordability** — Most platforms start at $20–60/user/month enterprise pricing; gap below $10/user/month for teams <500 people (Cloudflare $7 closest, but still requires enterprise upgrade for features).
- **Legacy protocol support** — Most ZTNA platforms favor modern protocols (OIDC, SAML); limited support for older auth mechanisms (NTLM, Kerberos) without workarounds.
- **Hardware-based device trust** — Limited integration of hardware-backed device identities (TPM, secure enclave) for stronger posture signals.
- **Peer-to-peer zero trust** — No platform yet provides pure P2P zero trust networking without centralized gateways or orchestration (distributed overlay network gap).
- **Quantum-resistant cryptography** — Limited deployment of post-quantum algorithms; Cloudflare mentions "quantum-safe" but full migration elsewhere unclear.
- **Cross-cloud identity correlation** — Limited ability to correlate identity trust across AWS IAM + Azure AD + GCP workload identity in single ZTNA policy.

### AI-Augmentation Candidates

Manual and rule-based features where AI could provide meaningfully better results than existing approaches:

- **Automatic policy generation** — ML learning from observed access patterns to auto-generate least-privilege ZTNA policies without manual authoring (none yet).
- **Natural-language policy authoring** — LLMs translating prose ("contractors 9–5 weekdays") into formal policies (none yet; significant usability improvement).
- **Continuous behavioral baselining** — ML models learning normal access patterns and detecting real-time deviations without static rules (partial in some; opportunity for sophistication).
- **Adaptive risk scoring** — AI models scoring access risk mid-session based on device posture, location drift, behavior signals, and threat intelligence (Zscaler, Palo Alto hint; maturity gap).
- **Automated incident response** — AI agents quarantining sessions, blocking users, or escalating when compromise indicators detected (none fully autonomous yet).
- **Predictive policy violation** — Models forecasting which users/devices are likely to attempt policy violations and proactively adjusting rules or training (none yet).
- **Cross-cloud identity trust correlation** — Graph-based AI modeling trust across AWS IAM + Azure AD + GCP identities for unified ZTNA policies (none yet).
- **Dynamic credential generation** — AI learning credential usage patterns and auto-rotating/revising credentials to minimize exposure (partial in Vault; opportunity for sophistication).

## Legal & IP Summary

All commercial solutions reviewed are proprietary SaaS offerings with no identified copyright or licensing conflicts. Teleport, Boundary, and OpenZiti are open-source (Apache 2.0 / BSL) with commercial support options available; no licence compatibility issues identified.

No known patent encumbrances identified. NIST SP 800-207 (zero trust architecture) is government guidance, not patented. Industry concepts (BeyondCorp, Software-Defined Perimeter) are research publications, not IP-protected.

No material was omitted due to copyright or licensing uncertainty; all information sourced from public product pages, documentation, or credible reviews.

## Recommended Feature Scope

Based on the cross-cutting analysis above, here is a prioritised feature scope for a new ZTNA entrant:

**Must-have (MVP)**
- Identity verification integration (SAML, OIDC; support for major IdPs: Okta, Azure AD, Google Workspace)
- Device posture checking (OS version, encryption, antivirus, MDM enrollment)
- Granular access policy engine (user, device, application, time-based rules; ABAC or RBAC)
- Support for web applications, SSH, and RDP (3 application types minimum)
- Audit logging and compliance reporting (SOC 2, HIPAA, FedRAMP evidence)
- Session recording for SSH/RDP
- MFA enforcement
- Dashboard showing active sessions, policy compliance, and risk summary
- Role-based admin access control

**Should-have (v1.1)**
- Continuous mid-session verification (re-evaluate trust every 15–60 minutes)
- Application-aware routing (QoS, geographic preference)
- Support for Kubernetes and microservices (service-to-service zero trust)
- Database access with proxy and encryption
- API access control (OAuth 2.0 scope enforcement)
- Advanced threat detection (anomalous access patterns)
- Integration with CASB or DLP for data protection layer
- Automated policy recommendation engine (suggest rules from observed access)
- Multi-cloud support (AWS, Azure, GCP)
- Compliance-driven policy templates (FedRAMP, HIPAA, PCI-DSS)

**Nice-to-have (backlog)**
- AI-driven policy auto-generation from observed patterns
- Natural-language policy authoring
- Adaptive risk scoring with behavioral baselining
- Automated remediation (quarantine sessions on breach indicators)
- Peer-to-peer zero trust networking (no centralized gateway)
- Hardware-backed device trust (TPM, secure enclave)
- Post-quantum cryptography (quantum-resistant algorithms)
- Voice/video call controls (ZTNA for communications)
- Cross-cloud identity correlation (AWS IAM + Azure AD + GCP unified)
- Predictive breach risk forecasting
