## 1. Detection – Honeytokens
Detection of honeytoken account access

## 2. Description
This use case aims to detect attackers by generating alerts when activity involving a honeytoken account is observed.

When creating a honeytoken account, the main objectives are:

* Design an account that appears valuable to attackers but poses no risk to your organization’s security
* Imitate the structure of administrator or service accounts—without granting any actual administrative or service permissions
* Apply Identity Protection policies to monitor and safeguard these accounts, making them attractive bait while keeping your data secure

Attackers are increasingly aware of honeytoken techniques and often attempt to avoid triggering them. To increase the chances of engagement, it’s essential to ensure honeytoken accounts follow the same naming conventions and patterns as legitimate user accounts within your organization.

Honeytokens within Falcon Identity Protection -> https://supportportal.crowdstrike.com/s/article/ka16T000001MfykQAC

## 3. Data Sources
**Primary Data Source:** CrowdStrike Falcon Identity events (`event_simpleName=/UserLogon.*/i`)

## 4. Query
```
// Detects logins involving default administrator accounts
#event_simpleName = /UserLogon.*/i
// Adjust or extend this to match your custom honeytoken accounts
| UserSid = /S-1-5-21-\d*-\d*-\d*-500/i
```
