# Standards & API Reference

> Project: Zero Trust Network Access · Generated: 2026-05-03

## Industry Standards & Specifications

### ISO Standards

- **ISO/IEC 27001:2022** — Information security management systems; Annex A control A.8.20 (networks security) and A.8.22 (segregation of networks) directly govern network access control requirements. URL: https://www.iso.org/standard/82875.html

- **ISO/IEC 27002:2022** — Guidance for ISO 27001 controls; Section 8.20 provides network security controls including zero trust segmentation principles and least-privilege access. URL: https://www.iso.org/standard/75652.html

- **ISO/IEC 29146:2016** — Framework for access management; defines concepts and principles for controlling access to resources, aligning with zero trust policy enforcement models. URL: https://www.iso.org/standard/45247.html

### W3C & IETF Standards

- **RFC 6749 — OAuth 2.0 Authorization Framework** — The foundational authorization protocol used by all ZTNA solutions for delegating access. Combined with PKCE (RFC 7636) for secure public client flows. URL: https://datatracker.ietf.org/doc/html/rfc6749

- **RFC 8705 — OAuth 2.0 Mutual TLS Client Authentication** — Enables mTLS-based client authentication for high-assurance workload-to-service access, critical in zero trust service mesh scenarios. URL: https://datatracker.ietf.org/doc/html/rfc8705

- **RFC 8693 — OAuth 2.0 Token Exchange** — Enables SPIFFE/SPIRE workload identity federation with enterprise OAuth authorization servers, allowing service accounts to exchange credentials across trust domains. URL: https://datatracker.ietf.org/doc/html/rfc8693

- **RFC 7519 — JSON Web Token (JWT)** — Standard token format used in zero trust access assertions, carrying identity claims, device posture, and policy attributes between ZTNA components. URL: https://datatracker.ietf.org/doc/html/rfc7519

- **RFC 9110 — HTTP Semantics** — Defines standards-based HTTP security requirements including header-based identity propagation used in zero trust proxy architectures. URL: https://datatracker.ietf.org/doc/html/rfc9110

### Data Model & API Specifications

- **OpenAPI 3.1** — All major ZTNA vendors (Cloudflare, Zscaler, Palo Alto) expose REST management APIs described with OpenAPI 3.1, enabling Terraform providers, SDKs, and automation pipelines. URL: https://spec.openapis.org/oas/latest.html

- **SPIFFE — Secure Production Identity Framework for Everyone** — CNCF-graduated standard defining SVIDs (SPIFFE Verifiable Identity Documents) in X.509 and JWT formats for workload-to-workload zero trust authentication without static credentials. URL: https://spiffe.io/

- **SPIRE — SPIFFE Runtime Environment** — The reference implementation of SPIFFE; provides APIs for workload attestation, SVID issuance (recommended 1-hour lifetime with automated rotation), and federation across trust domains using HTTPS/mTLS bundle exchange. URL: https://spiffe.io/docs/latest/spire-about/spire-concepts/

- **WireGuard Protocol** — Modern VPN tunnelling protocol underlying open-source ZTNA solutions (NetBird, Tailscale); provides cryptographically authenticated, lightweight peer-to-peer tunnels. URL: https://www.wireguard.com/

### Security & Authentication Standards

- **NIST SP 800-207 — Zero Trust Architecture (2020)** — The foundational NIST standard defining zero trust principles: verify explicitly, use least privilege, assume breach. Defines the Policy Decision Point (PDP) and Policy Enforcement Point (PEP) architecture model used by all major ZTNA platforms. URL: https://csrc.nist.gov/pubs/sp/800/207/final

- **NIST SP 800-207A — Zero Trust Architecture for Cloud-Native Applications in Multi-Cloud Environments** — Extension of SP 800-207 covering ZTNA implementation in multi-cloud and containerised workload scenarios. URL: https://csrc.nist.gov/pubs/sp/800/207/a/final

- **NIST SP 1800-35 — Implementing a Zero Trust Architecture (June 2025)** — Final NCCoE practice guide documenting 24-vendor collaborative ZTA implementations covering Enhanced Identity Governance (EIG), Software-Defined Perimeter (SDP), and microsegmentation approaches. URL: https://csrc.nist.gov/pubs/sp/1800/35/final

- **NIST SP 800-63B-4 (Draft) — Digital Identity Guidelines: Authentication** — Defines AAL1-AAL3 assurance levels; ZTNA platforms enforce AAL2 minimum (phishing-resistant MFA) and AAL3 for high-value resources. URL: https://csrc.nist.gov/publications/detail/sp/800-63b/4/draft

- **CISA Zero Trust Maturity Model v2.0 (2023)** — US federal guidance defining five zero trust pillars (Identity, Devices, Networks, Applications & Workloads, Data) with Traditional → Initial → Advanced → Optimal maturity stages. URL: https://www.cisa.gov/resources-tools/resources/zero-trust-maturity-model

- **NIST CSF 2.0 — Cybersecurity Framework** — PR.AC (Protect: Access Control) and DE.CM (Detect: Continuous Monitoring) functions directly map to ZTNA capabilities. URL: https://www.nist.gov/cyberframework

- **OWASP API Security Top 10** — Governs how ZTNA management APIs must be secured; API1 (Broken Object Level Authorization) and API3 (Broken Object Property Level Authorization) are particularly relevant to policy API design. URL: https://owasp.org/API-Security/

- **PCI DSS v4.0 — Requirement 1** — Network access controls and microsegmentation requirements for cardholder data environments; ZTNA architectures are increasingly used as a PCI-compliant alternative to traditional firewall-based segmentation. URL: https://www.pcisecuritystandards.org/

- **GDPR Article 32 — Security of Processing** — Requires appropriate technical measures including access control; ZTNA per-request authentication and audit logging support GDPR compliance obligations for organisations processing EU personal data. URL: https://gdpr-info.eu/art-32-gdpr/

### MCP Server Specifications

ZTNA and zero trust networking are actively integrating with the Model Context Protocol (MCP) ecosystem:

- **NetBird MCP Server** — Community-developed, officially recognised MCP server enabling AI agents to manage NetBird zero trust networks (create access policies, manage peers, inspect network state). URL: https://lobehub.com/mcp/xnet-ngo-mcp-netbird

- **Tailscale MCP Server** — Community project providing MCP tools for Tailscale resource management using the official Tailscale Go client library v2, with OpenAPI-powered tool descriptions. URL: https://github.com/pnocera/tailscale-mcp-server

- **Tailscale + MCP Connectivity** — Tailscale published a reference architecture (January 2026) for securing MCP server connectivity within ZTNA networks, preventing unauthenticated AI agent access to sensitive internal MCP services. URL: https://tailscale.com/blog/model-for-mcp-connectivity-lee-briggs

---

## Similar Products — Developer Documentation & APIs

### Cloudflare Zero Trust (Cloudflare Access)

- **Description:** Cloud-delivered ZTNA solution securing access to self-hosted, SaaS, and non-web applications without a VPN, backed by Cloudflare's 310+ city global edge network. Part of the Cloudflare One SASE platform.
- **API Documentation:** https://developers.cloudflare.com/api/resources/zero_trust/
- **Developer Guide:** https://developers.cloudflare.com/cloudflare-one/ and https://developers.cloudflare.com/cloudflare-one/api-terraform/
- **SDKs/Libraries:** Python SDK (cloudflare-python), Go SDK (cloudflare-go), Terraform provider (cloudflare/cloudflare)
- **Standards:** REST/JSON, OpenAPI 3.1, Terraform IaC
- **Authentication:** Bearer token (API Key or API Token with scoped permissions); OAuth 2.0 for user access flows

### Zscaler Private Access (ZPA)

- **Description:** Cloud-native ZTNA platform deploying lightweight App Connectors that create outbound-only connections to the Zero Trust Exchange, eliminating inbound firewall ports.
- **API Documentation:** https://help.zscaler.com/zpa/understanding-zpa-api and https://automate.zscaler.com/docs/docs/api-reference-and-guides/api-reference/zpa
- **SDKs/Libraries:** zscaler-sdk-python v2.x (PyPI, public beta 2026), zscaler-sdk-go (GitHub: zscaler/zscaler-sdk-go)
- **Developer Guide:** https://help.zscaler.com/zpa/getting-started-zpa-api
- **Standards:** REST/JSON, OpenAPI (Swagger), Postman collections available
- **Authentication:** OAuth 2.0 client credentials (client_id, client_secret, customer_id, cloud)

### Palo Alto Prisma Access

- **Description:** Cloud-delivered SASE platform extending Palo Alto next-generation firewall (NGFW) capabilities to cloud-delivered ZTNA, SD-WAN, and security services.
- **API Documentation:** https://pan.dev/access/api/prisma-access-config/
- **SDKs/Libraries:** Palo Alto pan-python SDK; Terraform provider (PaloAltoNetworks/terraform-provider-sase); Ansible collection
- **Developer Guide:** https://pan.dev/ (Palo Alto Networks developer portal)
- **Standards:** REST/JSON, XML API (Panorama legacy), OpenAPI 3.1 (newer SSE APIs with /sse URI prefix)
- **Authentication:** OAuth 2.0 service account tokens; Prisma Access Tenant Service Account

### NetBird (Open Source)

- **Description:** Open-source (BSD-3-Clause) ZTNA platform built on WireGuard, providing a self-hosted alternative to Tailscale and Cloudflare Access; raised €8.5M Series A in January 2026.
- **API Documentation:** https://docs.netbird.io/
- **SDKs/Libraries:** Go client (embedded); REST API with Swagger docs; official MCP server support
- **Developer Guide:** https://docs.netbird.io/
- **Standards:** REST/JSON, WireGuard protocol, OpenAPI
- **Authentication:** OAuth 2.0 / OIDC for user identity; PAT (Personal Access Tokens) for API access

### Tailscale

- **Description:** Mesh VPN/ZTNA service built on WireGuard; uses the Noise protocol for key exchange and provides per-device access control via ACL policies. Control plane is proprietary (open-source client, Headscale for self-hosted control plane).
- **API Documentation:** https://tailscale.com/docs/reference/tailscale-api and https://tailscale.com/api-docs
- **SDKs/Libraries:** tailscale-api Python package (v0.8.0, April 2026); Rust library (tailscale-api crate); Terraform provider; Pulumi package
- **Developer Guide:** https://tailscale.com/docs/reference
- **Standards:** REST/JSON, OpenAPI, Terraform/Pulumi IaC
- **Authentication:** OAuth 2.0 clients for ongoing automation; API key for personal access

### OpenZiti (Open Source)

- **Description:** CNCF-hosted open-source zero trust overlay network providing embedded zero trust at the application layer via SDKs; enables dark-by-default application exposure without public listener ports.
- **API Documentation:** https://openziti.io/ and GitHub: openziti/ziti
- **SDKs/Libraries:** SDKs for Go, Java, Python, .NET, Swift, Android
- **Developer Guide:** https://openziti.io/docs/introduction/
- **Standards:** WireGuard-compatible tunnelling, SPIFFE-compatible identity, mTLS
- **Authentication:** X.509 certificate-based workload identity; JWT for identity enrollment

### Cisco Secure Access (formerly Duo + Umbrella)

- **Description:** Cisco's unified ZTNA and SSE platform combining Duo MFA, Umbrella CASB, and Cisco Secure Client (AnyConnect 5.x) with a Zero Trust Access module for adaptive policy enforcement.
- **API Documentation:** https://duo.com/docs and https://developer.cisco.com/docs/secure-access/
- **SDKs/Libraries:** Duo Admin API Python client; Cisco Secure Access REST API
- **Developer Guide:** https://duo.com/docs/adminapi
- **Standards:** REST/JSON, RADIUS, SAML 2.0, OIDC
- **Authentication:** Duo API key (integration key + secret key); OAuth 2.0 for SSO flows

### Appgate SDP

- **Description:** Software-Defined Perimeter (SDP) zero trust platform implementing the Cloud Security Alliance SDP specification; strong in enterprise on-premises and hybrid deployments.
- **API Documentation:** https://www.appgate.com/developer
- **SDKs/Libraries:** REST API with OpenAPI spec; Terraform provider; Go SDK
- **Developer Guide:** Appgate developer portal (requires account)
- **Standards:** REST/JSON, OpenAPI, CSA SDP specification, SAML 2.0, OIDC
- **Authentication:** OAuth 2.0 client credentials; mTLS for administrative API access

### Octelium (Open Source)

- **Description:** Next-generation FOSS self-hosted unified zero trust platform (Apache 2.0) operating as ZTNA, API/AI/MCP gateway, PaaS, and ngrok alternative; notable for native MCP gateway support.
- **API Documentation:** https://github.com/octelium/octelium
- **SDKs/Libraries:** Go SDK; gRPC/REST APIs
- **Developer Guide:** https://octelium.com/solutions/open-source-ztna
- **Standards:** gRPC, REST/JSON, SPIFFE-compatible, WireGuard, MCP gateway
- **Authentication:** SPIFFE SVIDs; OAuth 2.0 / OIDC; mTLS

---

## Notes

- **SPIFFE/SPIRE adoption accelerating**: SPIFFE has become the de facto standard for workload identity in zero trust architectures, with CNCF graduation and integration into Kubernetes, Istio service mesh, and major cloud providers. Workload SVIDs with 1-hour lifetimes and automated rotation represent best practice.

- **MCP + ZTNA convergence (2025-2026)**: As AI agents proliferate, ZTNA platforms are being extended to secure MCP server access, preventing unauthenticated AI agents from accessing sensitive internal APIs. Tailscale, NetBird, and Octelium all have documented MCP integration patterns.

- **NIST SP 1800-35 (June 2025)**: The final NCCoE practice guide is the most comprehensive implementation reference, documenting real-world deployments with 24 vendors across SDP, EIG, and microsegmentation approaches.

- **Open source landscape**: NetBird (BSD-3-Clause), OpenZiti (Apache 2.0), and Octelium (Apache 2.0) represent production-grade open-source ZTNA options; Headscale provides an open-source Tailscale control plane alternative.
