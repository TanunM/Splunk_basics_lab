# Splunk_Basic_lab

## Introduction
This document outlines a hands-on project designed to introduce fundamental concepts and practical skills in Splunk. Through a series of task focused on analyzing real-world security data (SSH, HTTP, and network connection logs), this project demonstrates how to ingest data, use the Splunk Search Processing Language (SPL) for threat detection, and generate valuable security insights.

## Objective
The primary objective of this project is to gain practical proficiency in:
* Deploying and managing a local instance of Splunk Enterprise on a Linux operating system.
* Ingesting security log formats and configuring new data indexes.
* Utilizing the Splunk Search Processing Language to conduct effective security analysis.
* Identifying potential attackers (brute-force attempts).
* Analyzing web traffic for suspicious activity (scripted attacks, large file transfers).
* Investigating network metadata (Zeek connection logs) and unauthorized access attempts.
* Creating basic reports and statistical tables to summarize security events.

## Requirements and Tools
| Category | Requirement | 
|----------|-------------|
| OS | Ubuntu |
| Software | Splunk |
| Log Files | SSH logs, HTTP logs, Zeek connection logs, Unauthorized logs |

## Step 1: Download and Install Splunk
1. Register/login to the Splunk website. From there, click on the 60-day trial, and it will take you to the Splunk download page.
2. For Ubuntu devices, you can use the "wget" command-line prompt or download it by clicking on Linux and selecting the .deb version.
3. After downloading the software, install it first by navigating to the folder and using the following command:
```bash
sudo dpkg -i splunk…linux-amd64.deb
```

## Step 2: Enable Splunk as a Service
1. To find where splunk is installed use the following command:
```bash
whereis splunk
```
2. Now navigate to the directory:
```bash
cd /opt/splunk/bin
```
3. Enable Splunk and accept the license agreement using the command:
```bash
sudo ./splunk enable boot-start --accept-license
```
4. You will be prompted to set up an administrative account by providing a username and password.
After setting up the account, start the service:
```bash
sudo ./splunk start
```
5. Access the web interface by using the machine IP on port 8000 and log in using the credentials:
```
http://<ubuntu IP>:8000
```
6. You can find your IP using the "ip -a" command.
7. In the reference link the file links are provided, download the file and you can run Splunk Search Processing Language to find specific events.

## Step 3: SSH Log Analysis
1. Upload file
  * Upload the file to Splunk by going to Settings > Add Data.
  * Choose Upload and select the file.
  * Set Source type: json
  * Create a new index: ssh_lab
  * Finish the upload and confirm indexing.

2. List the endpoints with failed SSH login attempts:
```bash
index=ssh_lab sourcetype="json" auth_success=false | stats count by "id.orig_h" | sort -count
```
3. Find the number of total SSH connections:
```bash
index=ssh_lab sourcetype="json" | stats count as total_ssh_connections
```
4. Count all event types:
```bash
index=ssh_lab sourcetype="json" | stats count by event_type
```

## Step 4: HTTP Log Analysis
1. Upload the file in a similar manner to the SSH file upload.
2. Find the endpoints generating web traffic:
```bash
index=http_lab sourcetype="json" | stats count by "id.orig_h" | sort -count
```
3. Count the number of server errors between 500 and 600:
```bash
index=http_lab sourcetype="json" status_code>=500 status_code<600 | stats count as server_errors
```
4. Identify User-Agents associated with possible scripted attacks:
```bash
index=http_lab sourcetyp="json" user_agent IN ("sqlmap/1.5.1", "curl/7.68.0", "python-requests/2.25.1", "botnet-checker/1.0") | stats count by user_agent
```
5. Find large file transfers more than 500KB:
```bash
index=http_lab sourcetype="json" resp_body_len>500000 | table ts "id.orig_h" "id.resp_h" uri resp_body_len | sort -resp_body_len
```

## Step 5: Zeek Connection Log Analysis
1. Similar to the SSH file, upload the Zeek file
2. Find the Client IPs:
```bash
index="zeek_conn_lab" sourcetype="json" | stats count by id.orig_h | sort -count
```
3. List Most Common Services:
```bash
index="zeek_conn_lab" sourcetype="json" | stats count by service | sort -count
```
4. Find Connections with Duration > 1 Second:
```bash
index="zeek_conn_lab" sourcetype="json" duration>1 | table ts id.orig_h id.resp_h service duration
| sort -duration
```
5. Identify the 10 Most Accessed Internal Servers:
```bash
index="zeek_conn_lab" sourcetype="json" | stats count by "id.resp_h" | sort -count | head 10
```

## Step 6: Investigating Unauthorized Access
1. Similar to the SSH file, upload the unauthorized access file with Index Name: unauth_lab.
2. Find total number of success events:
```bash
index="unauth_lab" sourcetype="json" result="success" | stats count as total_success_events
```
3. Find most common event triggered and captured:
```bash
index="unauth_lab" sourcetype="json" | stats count by event_type | sort -count
```
4. Find if a uid “1010” tried accessing a linux server. What is the logfile path accessed by him twice?
```bash
index="unauth_lab" sourcetype="json" uid="1010" | stats count by path | where count=2
```

## Key Learning
* Data Ingestion and Indexing: Successfully set up a local Splunk environment and configured multiple new indexes to logically separate different types of security logs (SSH, HTTP, Zeek, Unauthorized Access).
* Search Processing Language (SPL): Gained proficiency in core SPL commands:
* Filtering: Using index, sourcetype, and field-value pairs.
* Statistics: Using the stats command to group and count events.
* Formatting/Refining: Using the table command to select and present specific fields.
* Conditional Searching: Using IN and where operators for targeted analysis.
* Security Use Cases: Applied Splunk to real-world defensive scenarios:
* Identified potential brute-force attacks.
* Detected abnormal web traffic patterns indicative of scanning or exploitation attempts.
* Analyzed network flow metadata to understand connection patterns.
* Investigated specific user actions and access patterns during an unauthorized attempt simulation.

## Reference
* [Splunk Projects you need for SOC Analyst](https://www.youtube.com/watch?v=tLPExMFJLzo&t)
