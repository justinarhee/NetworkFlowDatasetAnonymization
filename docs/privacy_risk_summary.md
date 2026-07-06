# privacy_risk_summary.md

**CIARA/FIU Flow Dataset Anonymization Prototype — Privacy Risk Summary**

## What is protected

nfanon replaces every IP address (source, destination, next-hop, router/exporter)
with another IP address using **CryptoPAn prefix-preserving anonymization**. After
anonymization:

- Real host and network identities are no longer directly visible.
- The mapping is **consistent** such that the same real IP always maps to the same
  pseudonym. Relational analysis is still valid without exposing identities.
- The mapping is **prefix-preserving**: addresses in the same subnet stay in the
  same pseudonymized subnet.

## What remains exposed

Anonymizing IPs alone does **not** make a flow record fully anonymous. These
fields are preserved and can still leak information:

- **Ports and protocol** reveal the services in use (443 = HTTPS, 22 = SSH,
  53 = DNS, 3389 = RDP …).
- **Byte and packet counts** are a volume fingerprint as an unusual exact size can
  single out a specific transfer or host.
- **Timing** (start/end/duration) is a behavioral fingerprint and supports
  correlation across records.
- **TCP flags** expose connection behavior.
- The **prefix structure itself** is retained.

## Key risks of prefix-preserving pseudonymization

1. **Reversibility.** CryptoPAn is keyed and deterministic as it is
   *pseudonymization*, not irreversible anonymization. Anyone with the key can
   reverse the mapping. **The key must be protected and rotated.**
2. **Injection attacks.** An attacker who can inject flows with known IP
   addresses into the collection can observe how those addresses map and
   reconstruct the prefix tree.
3. **Fingerprinting / frequency analysis.** If an attacker already knows a few
   real IPs in the dataset (or the traffic pattern of a known host), the
   preserved prefix structure with the knowledge of other preserved fields can
   re-identify hosts.

## Key management

- The anonymization key should **never** be committed, shared, documented, printed in
  logs, or stored in a public folder. Only a short fingerprint is logged.
- Stored locally in `secret/anon.key` or in the `$NFANON_KEY`
  environment variable; `.gitignore` excludes `secret/` and `*.key`.
- **Rotate the key per release.** A new key yields an entirely different mapping,
  which prevents correlating one release against another.

## Project Scope and Areas of Improvement

While prefix preservation keeps the subnet-level structure so analysis still works on anonymized data,
it also exposes the system to injection and fingerprinting attacks, and the key makes the mapping reversible.

For this assignment the anonymization is deliberately scoped to **nfanon on IP
fields only**, because the task requires time, ports, protocol, packets, bytes,
and flags to remain unchanged for analysis. If a future phase needs stronger
guarantees for wider data sharing, the following would be evaluated **without
breaking the required-preserved fields** unless explicitly permitted:

- generalizing timestamps (coarser time buckets) to weaken timing correlation,
- suppressing or generalizing rare flow profiles (k-anonymity) to remove unique
  fingerprints,
- bucketing byte/packet volumes to blur volume fingerprints,
- differential-privacy noise applied only to **published aggregate statistics**
  (never to per-record fields as it would corrupt protocol syntax).

These are noted as suggested next steps, not part of the current nfanon-based prototype.
