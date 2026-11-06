<img width="1000" height="1017" alt="IMG_6532" src="https://github.com/user-attachments/assets/348cc0b8-e4b0-412e-aa56-f8ea39e0fb17" />


SentinelOne ThreatOps: Singularity Data Lake  Threat Hunting

Overview

This repository documents hands-on threat hunting and endpoint detection investigations completed during the SentinelOne ThreatOps Challenge hosted via Root the Box and Women in Cybersecurity (WiCyS).  

Using SentinelOne Singularity Data Lake, the objective was to analyze raw enterprise endpoint telemetry across progressive incident scenarios, reconstruct attack lifecycles, and extract indicators of compromise using targeted SDL syntax, regular expressions, and schema shortcuts.  

Technical Tooling & Query Techniques

• Platform: SentinelOne Singularity Data Lake 

• Schema Shortcuts & Meta-Fields: #filepath, #username, #ip  

• Operators & Filtering: matches (regex), contains, contains:matchcase, autocomplete field discovery (dataSource.*)  

Telemetry Sources: Windows Event Log channels (Security, System, Sysmon), Endpoint Process Trees (PID, PPID), User Authentication records  
Mission Breakdown & Investigations.


Mission 1: Finding Nemo
•Focus: Platform orientation, baseline telemetry ingestion, and raw event filtering.

Core Tasks:
• Navigated Singularity Data Lake telemetry interfaces and validated active event streams across Windows endpoint fleets.  

• Constructed foundational keyword filters to triage high-volume event feeds and distinguish between background noise and anomalous host execution.  

Mission 2: Lake Placid
• Focus: Windows Event Log channel aggregation, telemetry profiling, and Process Lineage tracking.  

Key Challenge Investigations:
• Windows Event Channel Auditing (Rooting for the Croc)

• Queried the Windows Event Log channel distribution to identify high-volume monitoring streams.  

• Identified top telemetry-producing channels (event.channel / winlog.channel) across monitored workstations to establish ingestion baselines.  

• User Account Control (UAC) Elevation Tracing (The Last Bite)

• Target: Workstation Prod-DSK-WIN333.  

• Action: Investigated an elevation event tied to source process ID 5512 running consent.exe (the Windows binary responsible for prompting and brokering UAC permissions).  

• Analysis: Traced the process execution tree backwards using src.process.pid and tgt.process.parent.pid to locate the exact parent process ID (PPID) that invoked consent.exe, identifying the unprivileged software requesting privilege escalation.  

Mission 3: The Abyss
• Focus: Complex query operators, regex-based 
file hunting, and privileged identity auditing.

• Key Challenge Investigations:

• Ransomware Host Scoping (Damn Cold):

• Syntax: #filepath contains "conti"  

• Analysis: Leveraged the #filepath shortcut field to quickly aggregate file system modifications across all hosts, isolating the endpoint with the highest density of matching artifacts to determine patient zero / primary blast radius.  

• Targeted Regex Hunting (Lost the Crane!):

• Syntax: #filepath matches "Sensitive\\\\.*doc"  
• Analysis: Evaluated WastedLocker ransomware encryption behavior within protected file structures. Constructed regex strings with escaped backslashes to match document files within the Sensitive\ directory and identify encrypted payload outputs appending the .wasted extension rather than .conti.  

• Schema Discovery & Field Mapping (Tax Audit)

• Utilized the SDL Search Helper autocomplete engine to explore unindexed and context-dependent schema fields containing the dataSource namespace (dataSource.category, dataSource.name, dataSource.vendor).  

• Privileged Credential Activity (Perfluorocarbon)

• Syntax: #username contains "admin"  

• Analysis: Mapped shortcut meta-fields to aggregate user-context activity across multiple process and logon attributes. Filtered results to isolate and count verified successful logon events across elevated administrator accounts.

Mission 4: Jaws (Upcoming / In Progress)
• Advanced threat persistence mechanisms, lateral movement detection, and multi-endpoint correlation.

Key Takeaways

1. Shortcut Fields Optimize Detection Speed: Utilizing meta-shortcuts like #filepath and #username drastically reduces query authoring time during incident response by automatically mapping across fragmented OS field variants.

2. Escaping Backslashes in SDL Regex: File path pattern-matching inside SDL regex engines requires double-escaping (\\\\) to ensure Windows path separators are evaluated literally rather than interpreted as regex escape tokens.

3. Parent-Child Correlation for Privilege Exploits: Standalone alerts on consent.exe only indicate that elevation occurred; inspecting the PPID is required to identify the root execution vector.


<img width="1261" height="957" alt="IMG_6533" src="https://github.com/user-attachments/assets/601b2f43-d315-431b-9020-3f7e3477af6d" />
