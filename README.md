# SOC-Automation-Project: End-to-End SOAR with Wazuh, Shuffle, and TheHive

## Introduction
The intended purpose of this project was to gain practical hands-on experience in security **automation**, **detection**, and **response**, and attain valuable insight into the inner workings of a real-life security operations center (SOC) workflow. The modern SOC environment ingests a massive amount of alerts, commonly from numerous endpoints, which forces analysts to often respond to events that could have easily been automated, thus contributing to event fatigue and weakening security posture. To help alleviate some of the burden, a vast assortment of effective, scalable, and cost-effective tools were assembled into a comprehensive workflow that collects telemetry, enriches it with threat intelligence, and automates response actions. 

Although this project was used as a learning experience and thus does not have the complexity nor nuance required to automate complex SOC systems, the underlying design used is highly scalabe and cost effective. Using an orchestration platform like Shuffle, additional integrations and automated tasks can easily be implemented facilitating rapid adaptability to new threats, and allowing any SOC systems to configure automation and response to their own liking. The result is a system that not only improves efficiency, but also supports proactive security monitoring, where analysts can focus on high-value decision making instead of repetitive manual tasks.  

## Objective
The final objective of this project was to employ a vast assortment of scalable and cost-effective tools, and assemble them into an **end-to-end security** workflow that can successfully ingest and centralize telemetry collected from Windows and Linux endpoints, enrich suspicious indicators of compromise with external threat intelligence sources, and provide automatic alerting and case management for further investigations.

Additionally, this workflow was designed to notify the analyst of malicious activity via email and prompt them to take responsive action, such as blocking IP addresses.    

## Skills Demonstrated
* Designing end-to-end SOC workflows with automation in mind.
* Configuring endpoint telemetry on Windows and Linux systems.
* Setting up and configuring a SIEM (Wazuh) for correlation and alerting.
* Using Shuffle SOAR for automated workflows and API-based response.
* Enriching events with threat intelligence.
* Managing investigations and case data in TheHive.
* Writing playbooks for email alerting and analyst-driven decisions.
* Practicing incident response automation with active response.

## Tools
## Endpoint
<div> <a href="https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon"> <img src="https://img.shields.io/badge/-Sysmon-000000?&style=for-the-badge" /> </a> <a href="https://wazuh.com/"> <img src="https://img.shields.io/badge/-Wazuh-02569B?&style=for-the-badge" /> </a> </div>

### SOAR and Case Management  
<div>
  <a href="https://shuffler.io/">
    <img src="https://img.shields.io/badge/-Shuffle-FF6F00?&style=for-the-badge&logo=data:image/svg+xml;base64,[SHUFFLE_BASE64]&logoColor=white" />
  </a>
  <a href="https://thehive-project.org/">
    <img src="https://img.shields.io/badge/-TheHive-FFB400?&style=for-the-badge&logo=data:image/svg+xml;base64,[HIVE_BASE64]&logoColor=black" />
  </a>
</div>  


## Threat Intelligence
<div> <a href="https://www.virustotal.com/"> <img src="https://img.shields.io/badge/-VirusTotal-394EFF?&style=for-the-badge&logo=virustotal&logoColor=white" /> </a> </div>

## Cloud Provider
<div>
  <a href="https://www.digitalocean.com/">
    <img src="https://img.shields.io/badge/-DigitalOcean-0080FF?&style=for-the-badge&logo=digitalocean&logoColor=white" />
</a>
</div>

## Architecture
This project was divided into two distinct phases to demonstrate workflow reliability across different operating systems and highlight the flexibility of Wazuh for monitoring diverse endpoints. While the Windows phase focused on telemetry collection and case management, the Linux phase emphasized consistent active response.

Below is a high level overview visual representation of the intended end-to-end workflow: 
<div align="center" style="border: 2px solid #ccc; padding: 4px;">
  <img src="https://github.com/user-attachments/assets/bd0951da-d06b-4dfe-800c-cd3a45e6c8b5"
       alt="A diagram depicting the intended end-to-end workflow using Wazuh, Shuffle, and TheHive."
       width="512" height="491">
  <p><em>Figure 1: A diagram depicting the intended end-to-end workflow using Wazuh, Shuffle, and TheHive.</em></p>
</div>


**Phase 1:**

During the first phase, a **Windows** machine which was hosted as a virtual machine, and would have **Sysmon** installed in order to collect detailed event logs. This machine would serve as an endpoint from which a **Wazuh Agent** would forward all telemetry to the **Wazuh Manager** for correlation and alerting. 

Wazuh alerts with a level 5 or greater would then be sent to **Shuffle** via a Webhook, from where they would be automatically queried by **VirusTotal** to enrich suspicious indicators of compromise (IoCs). Enriched alerts were then pushed to **TheHive**, creating structured cases for investigation. Finally, an email would automatically be sent summarizing the event and instructing the analyst to log in to the hive for further investigation. 


**Phase 2:**

For the second phase, the workflow was recreated on an **Ubuntu** machine which was hosted on the cloud. This choice was made because active response was far more consistent on Linux, especially when triggering automated actions such as blocking IP addresses. 

This time, Wazuh would only send repeated failed SSH login attempts to Shuffle via a Webhook, Shuffle would query VirusTotal to check the reputation of the source IP address, and send an email notification prompting the analyst to confirm or decline the blocking of a suspicious IP address. If confirmed, Shuffle obtained a valid token via a GET API request and then issued a PUT HTTP request to initiate the blocking action.

## Technical Implementation Walkthrough (Phase 1)
This section will be used to explain the exact steps taken to successfully set up and configure the first phase of this project.  
## Setting up Sysmon
Throughout this project, Microsoft’s **System Monitor (Sysmon)** was used as the underlying tool to capture security-related events that would be ingested by Wazuh from the Windows host.  

According to Microsoft’s documentation:  
> “System Monitor (Sysmon) is a Windows system service and device driver that, once installed on a system, remains resident across system reboots to monitor and log system activity to the Windows event log.”  

This makes Sysmon ideal for pairing with a SIEM like Wazuh, which can parse these logs to detect anomalies and potential malicious activity. 

On the Windows virtual machine a Sysmon binary package was downloaded which was provided by Microsoft Sysinternals, additionally a configuration file was used during Sysmons installation which was sourced from a sysmon-modular GitHub repository. This configuration file was used to define which events Sysmon monitors and which details are captured.
  <div align="center" style="border: 2px solid #ccc; padding: 4px;">
    <img width="620" height="435" alt="3" src="https://github.com/user-attachments/assets/f7f364df-138e-4a0b-a3b2-71ff46b7ed77" />
      <br> </br>
    <p><em>Figure 2: A screenshot taken to display the chosen repository for the Sysmon configuration file.</em></p>
  </div>
Both the configuration file and the Sysmon binary were placed in the same directory and installed via the following powershell command: 
<br> </br>

```
.\Sysmonx64.exe -i sysmonconfig.xml 
```
  <div align="center" style="border: 2px solid #ccc; padding: 4px;">
    <img width="603" height="312" alt="4" src="https://github.com/user-attachments/assets/188602b3-2375-4637-9e29-446283425365" />
    <p><em>Figure 3: A screenshot displaying a proof of concept Sysmon installation. </em></p>
  </div>

## Setting up and Configuring Wazuh
In order to successfully setup a "Security Information and Event Management" (SIEM) system two core components are required, "Agents" and a "Manager". "Agents", are lightweight software programs installed on endpoints that collect and forward security logs, while the manager acts as a central server that recieves logs from agents, and generates corresponding alerts. 

In the case of this project a cloud hosted Ubuntu server would act as the Wazuh manager while the afformentioned Windows virtual machine would facilitate the Wazuh agent.
the first step to set up the Wazuh SIEM was to log onto the Ubuntu server via SSH. 


```
ssh root@<ip address>
```

  <div align="center" style="border: 2px solid #ccc; padding: 4px;">
    <img width="687" height="159" alt="5" src="https://github.com/user-attachments/assets/65516bd7-f621-4d41-b243-6a2869f64406" />
    <p><em>Figure 4: A screenshot of a successful ssh logon onto the Ubuntu server. </em></p>
  </div>

  




















