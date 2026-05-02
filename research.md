# Zero Trust Network Access

> Candidate #151 · Researched: 2026-05-02

## Existing Products and Software Packages

| Tool | Description | Type | Pricing | Strengths / Weaknesses |
|------|-------------|------|---------|------------------------|
| Zscaler Private Access (ZPA) | Cloud-native ZTNA service connecting users to private apps without VPN | Commercial SaaS | Per-user subscription, enterprise quotes | Strengths: massive scale, integrated with Zscaler SSE; Weaknesses: expensive, cloud-only lock-in |
| Palo Alto Prisma Access (ZTNA 2.0) | Identity-based, application-specific access with continuous trust verification | Commercial SaaS/Cloud | Per-seat enterprise licensing | Strengths: deep inspection, broad platform integration; Weaknesses: complex configuration, high cost |
| Cloudflare Access | Zero trust access layer built on Cloudflare's global edge network | Commercial SaaS | Free tier up to 50 users; Teams plan ~$7/user/month | Strengths: low latency, easy onboarding, generous free tier; Weaknesses: less mature for complex enterprise routing |
| Cisco Duo + Cisco ZTNA | Identity-centric access control integrated with Cisco networking stack | Commercial SaaS | Per-user; varies by bundle | Strengths: deep Cisco ecosystem integration; Weaknesses: fragmented across product lines |
| Microsoft Entra Private Access | ZTNA capability within the Entra identity platform | Commercial SaaS | Bundled with Entra Suite or Microsoft 365 E5 | Strengths: seamless M365 integration; Weaknesses: limited to Microsoft-centric environments |
| Teleport | Open-source infrastructure access platform with ZTNA capabilities | Open Source / Commercial | Free OSS; Enterprise pricing by cluster | Strengths: developer-friendly, certificate-based; Weaknesses: primarily infra/SSH focus, less application-layer |
| Boundary (HashiCorp) | Identity-based access management for dynamic infrastructure | Open Source / Commercial | Free OSS; HCP Boundary enterprise SaaS | Strengths: Terraform/Vault integration; Weaknesses: requires HashiCorp stack investment |
| Netskope Private Access | ZTNA module within Netskope's Security Service Edge platform | Commercial SaaS | Per-user enterprise quotes | Strengths: strong DLP and CASB integration; Weaknesses: pricing opacity |
| Cato Networks | SD-WAN + ZTNA converged as a cloud-native SASE platform | Commercial SaaS | Per-user/site enterprise quotes | Strengths: unified networking and security; Weaknesses: less granular access policy control |
| OpenZiti | Open-source zero trust networking framework (embedded ZTNA) | Open Source | Free (Apache 2.0); NetFoundry commercial support | Strengths: embeddable in applications, truly open; Weaknesses: steep learning curve, immature ecosystem |

## Relevant Industry Standards or Protocols

- **NIST SP 800-207** — Foundational U.S. government zero trust architecture framework defining policy decision points (PDP) and policy enforcement points (PEP)
- **NIST SP 800-207A** — Extension to 800-207 covering ZTA in cloud-native and multi-cloud environments
- **NIST SP 1800-35** — Practical guide with 19 example ZTA implementations using commercial technologies
- **Software-Defined Perimeter (SDP) Specification** — Cloud Security Alliance (CSA) standard that underpins the "dark cloud" approach to ZTNA
- **BeyondCorp** — Google's internal zero trust model (published as research papers 2014–2018), widely cited as the conceptual origin of commercial ZTNA
- **OAuth 2.0 / OIDC** — Identity federation standards used by all ZTNA solutions for continuous identity verification
- **FIDO2 / WebAuthn** — Phishing-resistant authentication standard integral to strong ZTNA posture

## Available Research Materials

1. Rose, S., Borchert, O., Mitchell, S., & Connelly, S. (2020). *Zero Trust Architecture*. NIST Special Publication 800-207. https://csrc.nist.gov/pubs/sp/800/207/final — Peer-reviewed (NIST)
2. Ward, R., & Beyer, B. (2014). *BeyondCorp: A New Approach to Enterprise Security*. USENIX ;login: Vol 39, No 6. https://www.usenix.org/publications/login/dec14/ward — Peer-reviewed
3. Gilman, E., & Barth, D. (2017). *Zero Trust Networks: Building Secure Systems in Untrusted Networks*. O'Reilly Media. (Book, widely cited)
4. Stafford, V. (2020). *Zero Trust Architecture* (Draft SP 800-207). NIST. https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207-draft.pdf — Government publication
5. Scott, C. et al. (2023). *Implementing a Zero Trust Architecture* (SP 1800-35). NIST NCCoE. https://csrc.nist.gov/pubs/sp/1800/35/final — Government/Practice guide
6. Kindervag, J. (2010). *No More Chewy Centers: Introducing The Zero Trust Model Of Information Security*. Forrester Research. (Industry analyst report, not peer-reviewed)
7. Siriwardena, P. (2022). *Advanced API Security: OAuth 2.0 and Beyond*. Apress. (Book covering identity layer relevant to ZTNA)

## Market Research

**Market Size:** Estimated at USD 2.48 billion in 2025; projected to reach USD 4.18–14.74 billion by 2030–2033 at a CAGR of approximately 25%. North America holds ~42% of global revenue.

**Funding:** Zscaler (NASDAQ: ZS) market cap ~$30B; Cloudflare (NYSE: NET) ~$45B; significant private investment in Cato Networks (~$773M raised); Teleport raised ~$110M.

**Pricing Landscape:** Per-user SaaS subscriptions dominate. Cloudflare offers the most accessible entry (~$7/user/month); Zscaler and Palo Alto are enterprise-priced with custom quotes typically $20–$60/user/month. Open source options (OpenZiti, Teleport OSS) are free but require self-hosting expertise.

**Key Buyer Personas:** CISOs and security architects at enterprises with distributed workforces; IT directors replacing legacy VPN infrastructure; compliance-driven teams in finance, healthcare, and government.

**Notable Trends:** SASE convergence (combining ZTNA with SD-WAN); "universal ZTNA" covering both cloud and on-prem apps; ZTNA 2.0 adding continuous verification beyond initial connection; government mandates (U.S. OMB M-22-09) driving public-sector adoption.

## AI-Native Opportunity

- Continuous behavioural baselining to detect anomalous access patterns in real time, going beyond static RBAC rules
- AI-driven automatic policy generation from observed access patterns, reducing the manual overhead of least-privilege configuration
- Natural-language policy authoring ("Allow contractors to access the billing dashboard between 9–5 on weekdays") translated into enforcement rules
- Adaptive risk scoring that adjusts trust levels mid-session based on device posture, location drift, and user behaviour without requiring re-authentication
- Automated remediation: AI agent quarantines sessions or escalates to SOC analysts when continuous verification detects compromise indicators
