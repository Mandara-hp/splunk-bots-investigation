# Splunk Incident Investigation: BOTS v1 web server compromise

Investigation of a website attack in Splunk's **Boss of the SOC (BOTS) v1** dataset, using **SPL** across network, IDS and Windows host logs. I traced the attack from the first vulnerability scan to code running on the server, then built and tested a detection for the brute-force step.

> **Data:** BOTS v1 attack-only dataset (pre-indexed), from Splunk's public `splunk/botsv1` repository. The company, domain and network are fictional. No data is stored in this repo.

## Summary

On 10 August 2016, an attacker scanned `imreallynotbatman.com` with the **Acunetix** vulnerability scanner, **brute-forced** the Joomla admin password (`batman`), logged in, uploaded a **web shell** and a Windows executable (**`3791.exe`**), ran it through the website, gained interactive command shells on the web server **`we1149srv`**, and had the server download the defacement image from attacker infrastructure.

Two attacker IPs were used, and the evidence links them to one attacker: the password guessed by one IP was used to log in from the other.

| Role | Value |
| --- | --- |
| Victim website | `imreallynotbatman[.]com` (Joomla on IIS) |
| Victim web server | `192.168.250.70`, host `we1149srv` |
| Scanner / login / uploads | `40.80.148[.]42` |
| Brute force / file hosting | `23.22.63[.]114` |
| Malware | `3791.exe` |
| Web shell | `agent.php` |
| Defacement image source | `prankglassinebracket.jumpingcrab[.]com:1337` |

## Timeline (10 Aug 2016)

| Time | Source | What happened | Evidence |
| --- | --- | --- | --- |
| from ~22:41 | `40.80.148[.]42` | Acunetix scan: 17,483 of 18,718 requests to the site, full of SQL, command and code injection tests | `stream:http`, `suricata` |
| 22:45–22:50 | `23.22.63[.]114` | 412 dictionary password guesses against `/joomla/administrator/index.php` in one 5-minute window (~1.4 per second, automated) | `stream:http` form data |
| before 22:50 | `40.80.148[.]42` | Logs in with the guessed password `batman` | `stream:http` form data |
| 22:50:31 | `40.80.148[.]42` | Uploads `agent.php` through the Joomla admin page | `stream:http` |
| 22:51:11 | (src_ip not parsed) | Uploads `eXtplorer_2.1.5.zip`, a Joomla file-manager add-on | `stream:http` |
| 22:52:47 | (src_ip not parsed) | Uploads `3791.exe` and `agent.php` | `stream:http` |
| 22:56:18 | on `we1149srv` | `php-cgi.exe` → `cmd.exe /c "3791.exe 2>&1"` → `C:\inetpub\wwwroot\joomla\3791.exe` runs | Sysmon Event ID 1 |
| 22:58:23, 23:08:13 | on `we1149srv` | `3791.exe` spawns `cmd.exe`: interactive shell access | Sysmon Event ID 1 |
| 23:06:21, 23:13:46 | `192.168.250.70` → `23.22.63[.]114:1337` | Web server downloads `poisonivy-is-coming-for-you-batman.jpeg` | `stream:http` |

## Investigation, step by step

All searches use `index=botsv1` with the time range set to **All time** (the data is from 2016).

### 1. Which logs mention the website?
```
index=botsv1 imreallynotbatman.com | stats count by sourcetype
```
Four sources: `stream:http` (web traffic), `suricata` (IDS alerts), `iis` (web server), `fgt_utm` (firewall security events).

### 2. Who sent the most requests? (the scanner)
```
index=botsv1 sourcetype=stream:http imreallynotbatman.com | stats count by src_ip | sort -count
```
`40.80.148[.]42` sent 17,483 requests; `23.22.63[.]114` sent 1,235.

```
index=botsv1 sourcetype=stream:http src_ip=40.80.148.42 | stats count by http_user_agent | sort -count
```
The scanner posed as a Chrome browser, but also injected test payloads into the User-Agent field: SQL injection (`sleep(9)`), command injection (`$(nslookup …)`), and code injection marked `acunetix_wvs_security_test`. That identifies **Acunetix** (WVS = Web Vulnerability Scanner).

### 3. Which server was targeted?
```
index=botsv1 sourcetype=stream:http src_ip=40.80.148.42 | stats count by dest_ip | sort -count
```
`192.168.250.70` received 17,546 of 17,547 requests: the internal web server behind the firewall.

### 4. Which login page was attacked?
```
index=botsv1 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST | stats count by src_ip, uri_path | sort -count
```
`23.22.63[.]114` sent 412 POSTs to `/joomla/administrator/index.php` (the Joomla admin login) and nothing else: a brute force. The scanner's POSTs were spread across thousands of pages.

### 5. Which password worked?
```
index=botsv1 sourcetype=stream:http http_method=POST uri_path="/joomla/administrator/index.php" form_data=*passwd*
| rex field=form_data "passwd=(?<password>[^&]+)"
| stats count values(src_ip) as src_ips by password | where count>1
```
`rex` extracts the password from the login form. One password was used twice: **`batman`**, by `23.22.63[.]114` (which guessed it) and `40.80.148[.]42` (which logged in with it). This links both IPs to the same attacker.

### 6. What was uploaded?
```
index=botsv1 sourcetype=stream:http dest_ip=192.168.250.70 http_method=POST part_filename*
| table _time src_ip uri_path part_filename*
```
`agent.php`, `eXtplorer_2.1.5.zip`, then `3791.exe` with `agent.php`, all within about two minutes.

### 7. Did `3791.exe` run? (network → host)
```
index=botsv1 3791.exe | stats count by sourcetype
```
The file appears in 69 Sysmon events. Without the Sysmon add-on the XML is not split into fields, so they are extracted with `rex`:
```
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" 3791.exe
| rex "<EventID>(?<EventID>\d+)</EventID>"
| rex "<Data Name=.Image.>(?<Image>[^<]+)"
| rex "<Data Name=.ParentImage.>(?<ParentImage>[^<]+)"
| rex "<Data Name=.CommandLine.>(?<CommandLine>[^<]+)"
| search EventID=1
| table _time host Image ParentImage CommandLine
```
Sysmon Event ID 1 (process creation) shows `php-cgi.exe` (the website's PHP engine) starting `cmd.exe /c "3791.exe 2>&1"`, and `3791.exe` running from the web folder. A website launching a command prompt is the sign of a web shell. The network showed the file arrived; Sysmon proves it executed, and the parent process shows how.

### 8. Where did the defacement image come from?
```
index=botsv1 src_ip=192.168.250.70 jpeg | table _time sourcetype dest_ip site url uri_path
```
The web server itself downloaded `poisonivy-is-coming-for-you-batman.jpeg` from `prankglassinebracket.jumpingcrab[.]com` on port 1337 (`23.22.63[.]114`). A web server making outbound downloads, on an unusual port, is itself suspicious.

## Detection: brute force on the admin login

```
index=botsv1 sourcetype=stream:http http_method=POST uri_path="*/administrator/index.php"
| bin _time span=5m
| stats count by _time, src_ip
| where count > 20
```
Alerts when one IP sends more than 20 login attempts in 5 minutes.

| Test | Result |
| --- | --- |
| Catches the attack | Fires once: `23.22.63[.]114`, 412 attempts in the 22:45 window |
| Ignores look-alike activity | Does not fire on the scanner's 14 login POSTs |

**Limitation:** the attack-only dataset contains little normal admin-login traffic, so false positives from real users could not be fully tested. In production I would also alert on the successful login that follows a burst of failures, which matters more than the guessing itself.

## MITRE ATT&CK

| Technique | Where |
| --- | --- |
| T1595.002 Active Scanning: Vulnerability Scanning | Acunetix scan |
| T1110.001 Brute Force: Password Guessing | 412 admin login attempts |
| T1078 Valid Accounts | Login with the guessed admin password |
| T1505.003 Server Software Component: Web Shell | `agent.php` run through PHP |
| T1105 Ingress Tool Transfer | Upload of `3791.exe`; download of the image |
| T1059.003 Command and Scripting Interpreter: Windows Command Shell | `cmd.exe` launched by PHP and by `3791.exe` |
| T1491.002 Defacement: External Defacement | Defacement image fetched by the server |

## Problems I hit and how I solved them

| Problem | Cause | Fix |
| --- | --- | --- |
| Every search returned 0 events | Time picker defaulted to "Last 24 hours"; the data is from 2016 | Set **All time** |
| Phrase search `"multipart/form-data"` found nothing | Stream logs are JSON, which can store `/` as `\/` | Search on a field (`part_filename*`) instead of raw text |
| "1 event" but an empty `stats` table | `stats … by src_ip` drops rows where a field is empty; the field name also contained `{}` | Used `table`, which keeps every row, and a wildcard field name |
| `EventCode=1` found nothing in Sysmon | Sysmon data is raw XML and the add-on is not installed, so fields were not extracted | Extracted fields with `rex` |
| `*.jpeg` found nothing | Leading wildcards work poorly with Splunk's word splitting | Searched the plain word `jpeg` |

The general rule: when a search returns nothing, widen it (one plain keyword, no field names) to find where the data is, then narrow it again. A negative result is only meaningful once the search itself has been checked.

## Setup

- Splunk Enterprise 10.6 (free licence) on macOS (Apple Silicon), bound to `127.0.0.1` only (`SPLUNK_BINDIP`), so it is not reachable from the network
- BOTS v1 attack-only dataset, extracted into `$SPLUNK_HOME/etc/apps`; no add-ons installed

See [`searches.spl`](searches.spl) for every search in one file and [`iocs.csv`](iocs.csv) for the indicators.

## Related projects

- [Network Traffic Analysis Portfolio](https://github.com/Mandara-hp/network_traffic_analysis): five PCAP investigations in Wireshark/tshark, with Suricata rules tested against the captures
- [SOC-lab](https://github.com/Mandara-hp/SOC-lab): Elastic SIEM lab with Sysmon telemetry and ATT&CK-mapped detections
