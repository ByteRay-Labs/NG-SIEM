# Integrating MikroTik Logs into CrowdStrike NextGen SIEM

This guide outlines step-by-step how to integrate logs from a MikroTik router into CrowdStrike NextGen SIEM.

---

## Step 1: Add Parser to CrowdStrike NextGen SIEM

1. Download the `MikroTik.yaml` file from the repository.  
2. Navigate to **NextGen SIEM → Parsers**.  
3. Click **“Add new Parser”**.  
4. Enter the following details:  
   - **Name:** `MikroTik`  
   - **Template:** `Import`  
5. Upload the parser file using the **Upload** interface.  
6. Click **“Create”** to save the parser.

---

## Step 2: Configure the Log Source in CrowdStrike

1. Open **NextGen SIEM → Data Onboarding**.  
2. Select **Data Connections → +Add Connection**.  
3. Filter by **HEC** and choose the **“HEC/HTTP Event Connector”**.  
4. Fill in the required details and select the new **“MikroTik”** parser under **Parser**.  
5. Save the configuration.  
6. Click **“Generate API Key”** to create an API key for the connection between your Syslog Collector and the CrowdStrike Cloud.

---

## Step 3: Configure the Syslog Collector

### Fleet Manager  
It is recommended to deploy the LogCollector via **Fleet Management**. This allows centralized configuration and updates via the CrowdStrike console.

### Manual Installation

1. Install the **LogCollector**, which receives Syslog messages and forwards them to CrowdStrike.  
2. Edit the configuration file **`/etc/humio-log-collector/config.yaml`** accordingly.

3. On Windows systems:  
   - Restart the **Humio Service** after updating the configuration.

---

## Step 4: Configure the MikroTik Router

1. Under **System → Logging → Actions**, add the LogCollector as a remote log server.  
2. Configure the Syslog export with the following parameters:  
   - **Name:** `Syslog`  
   - **Remote Address:** `IP/Hostname of the LogCollector`  
   - **Remote Port:** `Port of the LogCollector`  
   - **Remote Log Format:** `CEF`  
   - **Remote Log Protocol:** `UDP`  
   - **Timestamp Format:** `ISO8601`

3. Go to **System → Logging → Rules** to configure the log rules.  
```config.yaml
dataDirectory: /var/lib/humio-log-collector
sources:
  ## MikroTik Collect syslog udp 514 
  syslog_mikrotik_udp:
    type: syslog
    mode: udp
    port: 514
    maxEventSize: 2048
    sink: syslog-mikrotik

sinks:
  ## This sink receives data from "syslog_mikrotik_udp" source above  
  syslog-mikrotik:
    type: hec
    proxy: none
    token:  ##############
    url: https://#######.ingest.eu-1.crowdstrike.com/services/collector
    maxEventSize: 910000
    maxBatchSize: 5242880
    workers: 4
```
4. Create a new rule with the following settings:  
   - **Topic:** Info, Warning, etc. (Select desired log sources)  
   - **Action:** `Syslog` (Name of the action)

**Note:** Logging of firewall rules must be enabled individually within each firewall rule. Be aware that this may lead to a significant volume of log data. It is also recommended to define a **Log Prefix** within the firewall rule to indicate the corresponding action—otherwise, this information will be missing in the log entries.
