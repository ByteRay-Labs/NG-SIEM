## 1. Hunting - Use of DoH (DNS over HTTPS)
Detection of DoH traffik to known DoH-providers

## 2. Data Sources
Primary Data Source: CrowdStrike Falcon DNS events (#event_simpleName = DnsRequest).

## 3. Query
```
#event_simpleName = DnsRequest
| in(field="DomainName", values=["cloudflare-dns.com", "dns.google", "dns.quad9.net","mozilla.cloudflare-dns.com"])
| groupBy(["ComputerName","ContextBaseFileName"])
```
