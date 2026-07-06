# privacy_risk_summary.md

**CIARA/FIU Flow Dataset Anonymization Prototype — Privacy Risk Summary**

## What is protected

nfanon replaces every IP address (source, destination, next-hop, router/exporter)
with a pseudonym using **CryptoPAn prefix-preserving anonymization**. After
anonymization:

- Real host and network identities are no longer directly visible.
- The mapping is **consistent** — the same real IP always maps to the same
  pseudonym — so relational analysis (who-talks-to-whom, top talkers) still works
  without exposing identities.
- The mapping is **prefix-preserving** — addresses in the same subnet stay in the
  same pseudonymized subnet — so subnet/ASN-level grouping still works.

## What remains exposed

Anonymizing IPs alone does **not** make a flow record fully anonymous. These
fields are preserved (by design, for analysis) and can still leak information:

- **Ports and protocol** reveal the services in use (443 = HTTPS, 22 = SSH,
  53 = DNS, 3389 = RDP …).
- **Byte and packet counts** are a volume fingerprint; an unusual exact size can
  single out a specific transfer or host.
- **Timing** (start/end/duration) is a behavioral fingerprint and supports
  correlation across records.
- **TCP flags** expose connection behavior (scans, resets).
- The **prefix structure itself** is retained — which is useful, but is also the
  thing an attacker exploits (below).

## Key risks of prefix-preserving pseudonymization

1. **Reversibility.** CryptoPAn is keyed and deterministic — it is
   *pseudonymization*, not irreversible anonymization. Anyone with the key can
   reverse the mapping. **The key must be protected and rotated.**
2. **Injection attacks.** An attacker who can inject flows with known IP
   addresses into the collection can observe how those addresses map and
   reconstruct the prefix tree.
3. **Fingerprinting / frequency analysis.** If an attacker already knows a few
   real IPs in the dataset (or the traffic pattern of a known host), the
   preserved prefix structure plus the preserved ports/volumes/timing can
   re-identify hosts.

## Key management (required practice)

- The anonymization key is **never** committed, shared, documented, printed in
  logs, or stored in a public folder. Only a short fingerprint is logged.
- Stored locally in `secret/anon.key` (perms `600`) or in the `$NFANON_KEY`
  environment variable; `.gitignore` excludes `secret/` and `*.key`.
- **Rotate the key per release.** A new key yields an entirely different mapping,
  which prevents correlating one release against another.

## Is prefix preservation useful or risky? Both.

- **Useful:** it keeps subnet-level structure so research (traffic per subnet,
  top talkers, DDoS/botnet clustering) still works on anonymized data.
- **Risky:** that same structure is what injection and fingerprinting attacks
  target, and the key makes the mapping reversible.

For this assignment the anonymization is deliberately scoped to **nfanon on IP
fields only**, because the task requires time, ports, protocol, packets, bytes,
and flags to remain unchanged for analysis. If a future phase needs stronger
guarantees for wider data sharing, the following would be evaluated **without
breaking the required-preserved fields** unless explicitly permitted:

- generalizing timestamps (coarser time buckets) to weaken timing correlation,
- suppressing or generalizing rare flow profiles (k-anonymity) to remove unique
  fingerprints,
- bucketing byte/packet volumes to blur volume fingerprints,
- differential-privacy noise applied only to **published aggregate statistics**,
  never to per-record fields (which would corrupt protocol syntax).

These are noted as next steps, not part of the current nfanon-based prototype.

## Bottom line

nfanon protects **identity** (IP addresses) while preserving **utility** for
traffic analysis. It does **not** by itself defeat injection or fingerprinting,
and it is reversible with the key — so the residual controls are strict key
management, key rotation, and limiting who receives the data.
