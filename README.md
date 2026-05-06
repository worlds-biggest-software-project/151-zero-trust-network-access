# Zero Trust Network Access

> Part of the [worlds-biggest-software-project](https://github.com/worlds-biggest-software-project) initiative.
>
> An open, AI-native zero trust access platform that replaces legacy VPNs with identity-based, continuously verified application access.

Zero Trust Network Access (ZTNA) is a software-defined perimeter that grants users access to private applications based on identity and context rather than network location. This project targets engineering and security teams who need granular, continuously verified access to web apps, SSH, RDP, Kubernetes, and databases without paying enterprise SaaS rates or accepting cloud-only lock-in.

---

## Why Zero Trust Network Access?

- Enterprise incumbents (Zscaler, Palo Alto, Netskope) charge $20–60 per user per month with custom quotes and pricing opacity, putting ZTNA out of reach for teams below 500 people.
- Cloud-only platforms like Zscaler Private Access create vendor lock-in and require connector deployment overhead, with no self-hosted path.
- Microsoft Entra Private Access only serves Microsoft-centric environments and weakens for non-Microsoft applications.
- Existing open-source options (Teleport, Boundary, OpenZiti) are infrastructure-focused, tied to a specific vendor stack, or carry a steep learning curve and immature ecosystem.
- No platform yet auto-generates least-privilege policies from observed access patterns or accepts natural-language policy authoring, leaving security teams stuck with manual rule writing.

---

## Key Features

### Identity & Device Trust

- Identity verification on every access attempt via SAML, OIDC, and major IdPs (Okta, Azure AD, Google Workspace)
- Device posture checks covering OS version, encryption, antivirus state, and MDM enrollment
- MFA enforcement integrated with the identity provider
- Certificate-based authentication as an alternative to shared secrets

### Granular Access Policy Engine

- Attribute-based and role-based access controls combining user, device, application, and time
- Application-specific policies for web apps, SSH, RDP, Kubernetes, databases, and APIs
- Compliance-driven policy templates aligned with SOC 2, HIPAA, FedRAMP, and PCI-DSS
- Centralized policy management across cloud and on-prem applications

### Continuous Verification & Session Control

- Mid-session re-evaluation of trust based on device posture, location, and behaviour
- Session recording for SSH and RDP for audit and forensics
- Adaptive risk scoring that adjusts trust levels without forced re-authentication
- Audit logging and compliance reporting suitable as evidence for regulated frameworks

### Multi-Cloud & Hybrid Deployment

- Outbound-only connector model so private applications are never exposed to the internet
- Multi-cloud support across AWS, Azure, and GCP, plus on-prem networks
- Application-aware routing with geographic preference
- Kubernetes and microservices support for service-to-service zero trust

---

## AI-Native Advantage

The project's AI focus targets the gaps incumbents have not closed: automatic policy generation from observed access patterns, natural-language policy authoring that translates prose like "allow contractors to access the billing app 9–5 weekdays" into enforcement rules, and continuous behavioural baselining for real-time anomaly detection. Adaptive risk scoring updates trust mid-session from device posture, location drift, and behaviour signals, and an automated remediation agent can quarantine sessions or escalate to SOC analysts when compromise indicators are detected.

---

## Tech Stack & Deployment

The project is designed to support self-hosted, cloud, and hybrid deployment. It aligns with NIST SP 800-207 and SP 800-207A zero trust architecture, the Cloud Security Alliance Software-Defined Perimeter specification, and identity standards including OAuth 2.0, OIDC, SAML, and FIDO2 / WebAuthn. Integrations target major identity providers, device management platforms, cloud provider APIs, and SIEM / logging systems, with connector-based access to private application networks.

---

## Market Context

The ZTNA market is estimated at USD 2.48 billion in 2025 and projected to reach USD 4.18–14.74 billion by 2030–2033 at roughly 25% CAGR, with North America accounting for ~42% of revenue. Pricing today ranges from Cloudflare Access at ~$7 per user per month up to Zscaler and Palo Alto enterprise quotes of $20–60 per user per month. Primary buyers are CISOs and security architects at distributed-workforce enterprises, IT directors replacing legacy VPNs, and compliance teams in finance, healthcare, and government driven by mandates such as U.S. OMB M-22-09.

---

## Project Status

> This project is in the **research and specification phase**.  
> Contributions, feedback, and domain expertise are welcome.

---

## Contributing

We welcome contributions from developers, domain experts, and potential users.
See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Important:** All contributions must be your own original work or clearly attributed
open-source material with a compatible licence. Copyright infringement and licence
violations will not be tolerated and will result in immediate removal of the offending
contribution. If you are unsure whether a piece of code, text, or other material is
safe to contribute, open an issue and ask before submitting.

---

## Licence

Licence to be determined. See [discussion](#) for context.
