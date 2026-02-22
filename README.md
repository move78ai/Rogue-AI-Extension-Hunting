Rogue-AI-Extension-Hunting

Hunting Rogue AI Extensions
Detection Engineering is a tactical function of a cybersecurity defense program that involves the design, implementation, and operation of detective controls with the goal of proactively identifying malicious or unauthorized activity. This repository provides SIEM threat hunting queries (Splunk, Sentinel, Elastic) to detect rogue browser extensions and info-stealers.
 
Overview
These rogue extensions often bypass MFA by stealing session cookies directly from the browser's local storage and scraping Document Object Model (DOM) data. They typically exfiltrate this data to attacker-controlled C2 servers like chatsaigpt.com and deepaichats.com every 30 minutes.

Repository Structure
Splunk: SPL queries for tracking Sysmon Event Code 11 drops, anomalous logins, and data exfiltration.

Sentinel: KQL queries targeting DeviceFileEvents to detect malicious .crx extension drops.

Elastic: EQL sequence rules correlating .crx file creations with C2 beaconing.

IOCs: Cryptographic extension IDs and known exfiltration domains for ingestion into your threat intelligence platforms.