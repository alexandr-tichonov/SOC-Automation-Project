# SOC-Automation-Project

## Introduction
The intended purpose of this project was to gain practical hands-on experience in security **automation**, **detection**, and **response**, and attain valuable insight into the inner workings of a real-life security operations center (SOC) workflow. The modern SOC environment ingests a massive amount of alerts, commonly from numerous endpoints, which forces analysts to often respond to events that could have easily been automated, thus contributing to event fatigue and weakening security posture. To help alleviate some of the burden, a vast assortment of effective, scalable, and cost-effective tools were assembled into a comprehensive workflow that collects telemetry, enriches it with threat intelligence, and automates response actions. 

Although this project was used as a learning experience and thus does not have the complexity nor nuance required to automate complex SOC systems, the underlying design used is highly scalabe and cost effective. Using an orchestration platform like Shuffle, additional integrations and automated tasks can easily be implemented facilitating rapid adaptability to new threats, and allowing any SOC systems to configure automation and response to their own liking. The result is a system that not only improves efficiency, but also supports proactive security monitoring, where analysts can focus on high-value decision making instead of repetitive manual tasks.  

## Objective
The final objective of this project was to employ a vast assortment of scalable and cost-effective tools, and assemble them into an **end-to-end security** workflow that can successfully ingest and centralize telemetry collected from Windows and Linux endpoints, enrich suspicious indicators of compromise with external threat intelligence sources, and provide automatic alerting and case management for further investigations.

Additionally, this workflow was designed to notify the analyst of malicious activity via email and prompt them to take responsive action, such as blocking IP addresses.    


## Architecture
This project was divided into two distinct phases to demonstrate workflow reliability across different operating systems and highlight the flexibility of Wazuh for monitoring diverse endpoints. While the Windows phase focused on telemetry collection and case management, the Linux phase emphasized consistent active response.

Below is a high level overview visual representation of the intended end-to-end workflow: 
<img width="512" height="491" alt="unnamed (1)" src="https://github.com/user-attachments/assets/bd0951da-d06b-4dfe-800c-cd3a45e6c8b5" />
*Figure 1: A diagram depicting the intended end-to-end workflow using Wazuh, Shuffle, and TheHive.* 

**Phase 1:**
During the first phase, a **Windows** machine was hosted on the cloud, and would have **Sysmon** installed in order to collect detailed event logs. This machine would serve as an endpoint from which a **Wazuh Agent** would forward all telemetry to the **Wazuh Manager** for correlation and alerting. 

Wazuh alerts with a level 5 or greater would then be sent to **Shuffle** via a Webhook, from where they would be automatically queried by **VirusTotal** to enrich suspicious indicators of compromise (IoCs). Enriched alerts were then pushed to **TheHive**, creating structured cases for investigation. Finally, an email would automatically be sent summarizing the event and instructing the analyst to log in to the hive for further investigation. 

**Phase 2**
For the second phase, the workflow was recreated on an **Ubuntu** host rather than Windows. This choice was made because active response was far more consistent on Linux, especially when triggering automated actions such as blocking IP addresses. 

This time, Wazuh would only send repeated failed SSH login attempts to Shuffle via a Webhook, Shuffle would query VirusTotal to check the reputation of the source IP address, and send an email notification prompting the analyst to confirm or decline the blocking of a suspicious IP address. If confirmed, Shuffle obtained a valid token via a GET API request and then issued a PUT HTTP request to initiate the blocking action.





