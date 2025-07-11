## 1. Hunting - Use of DoH (DNS over HTTPS)
Detection of DoH traffic to known DoH-providers

## 2. Description
DNS over HTTPS (DoH) encrypts DNS queries by tunneling them through HTTPS, making them indistinguishable from regular web traffic. While this improves user privacy, it also introduces blind spots for security teams. Why it matters:

- Phishing domains can be accessed without triggering DNS-based filtering.
- Command-and-Control (C2) communication can blend into normal HTTPS traffic.
- Data exfiltration becomes harder to detect as destination domains are hidden.

Impact on organizations:
Without proper monitoring or controls, DoH can undermine DNS visibility—one of the most critical layers in network security—allowing threats to go unnoticed.

## 2. Data Sources
Primary Data Source: CrowdStrike Falcon DNS events (#event_simpleName = DnsRequest).

## 3. Query
```
#event_simpleName = DnsRequest
| in(field="DomainName", values=["cloudflare-dns.com", "dns.google", "dns.quad9.net","mozilla.cloudflare-dns.com"])
| groupBy(["ComputerName","ContextBaseFileName"])
```
