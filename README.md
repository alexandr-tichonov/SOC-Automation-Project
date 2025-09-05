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
In order to successfully setup a "Security Information and Event Management" (SIEM) system two core components are required, "Agents" and a "Manager". "Agents", are lightweight software programs installed on endpoints that collect and forward security logs, while the "Manager" acts as a central server that recieves logs from agents, and generates corresponding alerts. 

In the case of this project a cloud hosted Ubuntu server would act as the Wazuh manager while the afformentioned Windows virtual machine would facilitate the Wazuh agent. the first step to set up the Wazuh SIEM was to log onto the Ubuntu server via SSH.
```
ssh root@<ip address> 
```
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> <img width="687" height="159" alt="5" src="https://github.com/user-attachments/assets/65516bd7-f621-4d41-b243-6a2869f64406" /> 
  <p><em>Figure 4: A screenshot of a successful ssh logon onto the Ubuntu server. </em></p> 
</div> 
After a successfull login the system was updated and a Wazuh package version of 4.7.0 was added and installed on the system. Once the installation completed, the provided admin credentials were promptly noted.

```
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="813" height="327" alt="6" src="https://github.com/user-attachments/assets/6d3d42dd-ac5b-4231-8f0b-7311a6763b6a" /> 
  <p><em>Figure 5: A screenshot showcasing the installation of Wazuh . </em></p> </div> <br></br> <div align="center" style="border: 2px solid #ccc; padding: 4px;"> <img width="811" height="132" alt="7-" src="https://github.com/user-attachments/assets/96bd3311-774c-4461-a83f-d480ac944a68" /> <p><em>Figure 6: A screenshot of the admin credentials provided. </em></p> </div> 

To access the Wazuh dashboard the Wazuh managers public IP address was inputted via a web browser on port ```443``` and the previously provided admin credentials were used for the login panel. ```https://<wazuh-dashboard-ip>:443```
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="689" height="493" alt="8(1)" src="https://github.com/user-attachments/assets/0d14f466-c775-428c-b548-b045ccef2539" /> 
  <p><em>Figure 7: A screenshot of the Wazuh dashboards login panel. </em></p> 
</div>

After successfully setting up the Wazuh Manager, the next step was to install a Wazuh agent on the Windows virtual machine. This was done by first clicking on the "Deploy New Agent" option available on the Wazuh dashboard. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="577" height="295" alt="9" src="https://github.com/user-attachments/assets/80ce89a1-a58d-46b4-aceb-5bdee700695b" /> 
  <p><em>Figure 8: A screenshot showcasing the "Deploy New Agent" option on the Wazuh Dashboard. </em></p> </div> 
  
  From the options presented, a Windows operating system was selected, with the server address being the Wazuh managers public IP address, the agent iteself was named as "Agent-2". 
  
  
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1599" height="1108" alt="blurred-e png" src="https://github.com/user-attachments/assets/362192dc-b2d1-4f35-989c-b69d7098cc39" /> <p><em>Figure 9: A screenshot of the options configured during agent setup. </em></p> 
</div> 

The Wazuh manager would then provide an installation command, that should be executed via PowerShell as administrator on the Windows virtual machine. Should the command not succeed it is possible to break it into two seperate segments.
```
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.12.0-1.msi -OutFile $env:tmp\wazuh-agent
msiexec.exe /i $env:tmp\wazuh-agent /q WAZUH_MANAGER='<IP address>' WAZUH_AGENT_NAME='<Agent Name>'
```
Once the command ran with no errors, the Wazuh service was started by using the following command:

```
net start wazuhsvc
```
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="941" height="127" alt="blurred-11 png" src="https://github.com/user-attachments/assets/df6ee3dd-a036-4d03-b470-3b328446a8ed" /> 
  <p><em>Figure 10: A screenshot showcasing a successful agent installation. </em></p> </div> 

Going back to the dashboard the prompt to deploy a new agent was now replaced with a visual representation, thus confirming that the agent setup was indeed successful. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> <img width="1159" height="299" alt="12" src="https://github.com/user-attachments/assets/dfee3c98-9cd5-42f2-b150-2beefb9843ac" /> <p><em>Figure 11: A visual representaion showing an active agent being operational. </em></p> </div> 

With the Wazuh agent successfully deployed on the Windows host, the next step was to ensure that Sysmon event logs were forwarded to the Wazuh Manager for analysis. By default, the Wazuh agent collects standard Windows event logs, but additional configuration is required to include Sysmon’s dedicated log channel.

In order to do so the ```ossec.conf``` configuration file located in the ```C:\Program Files (x86)\ossec-agent``` directory was modified via a text editor. To specify the Sysmon channel as a monitored log source, Sysmons ```Full Name``` must be specified which can be found in Microsofts Event Viewer, under the "Properties Section". 

Sysmons "Full Name" was determined to be: ```Microsoft-Windows-Sysmon/Operational``` 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
<img width="628" height="432" alt="13" src="https://github.com/user-attachments/assets/2d3f8510-5bc0-4a39-a84f-ce3de2c5590d" />
  <p><em>Figure 12: A screenshot of Sysmons Full Name listed in Windows Event Manager </em></p> 
</div> 

A new ```<localfile>``` block entry was then added into the ```ossec.conf``` configuration file:
```
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="771" height="410" alt="14" src="https://github.com/user-attachments/assets/09c42066-dbfe-4644-bf98-bc7cc7450849" />  
  <p><em>Figure 13: A screenshot of the entry made in the ossec.conf configuration file. </em></p> 
</div> 

After saving the configuration file, the Wazuh service was restarted to apply the changes:  
```
net stop wazuhsvc
net start wazuhsvc
```
This ensured that all Sysmon-generated security events were ingested by the Wazuh agent and forwarded to the Manager for correlation and alerting.

## Setting up TheHive 
With a log collection system in place, a case management system would now have to be implemented using **TheHive**, which is an open-source Security Incident Response Platform (SIRP) used for alert tracking and case management. 

It requires a few core dependencies being: 
"Java" - which runs TheHive application, "Cassandra" - which stores case data and observables, and "Elasticsearch" - which enables the searching and indexing of incdents. 


Before installing anything on the server, an SSH connection to TheHive server was established and preliminary dependencies for "TheHive 5", were installed. 
```
apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-release
```

The first step in preparing the server for TheHive was to install a supported Java runtime environment, in this case the "Amazon Corretto 11 distribution" was selected.
The following commands were executed to add the Corretto repository, update packages, and install Java 11:
```
wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor  -o /usr/share/keyrings/corretto.gpg
echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
sudo apt update
sudo apt install java-common java-11-amazon-corretto-jdk
echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment 
export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
```
One can easily check if Java was successfully installed by running the ```java --version``` command.
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="812" height="88" alt="15-" src="https://github.com/user-attachments/assets/c7aea371-a154-4288-b451-0d170aa0b340" />
  <p><em>Figure 14: A screenshot show a successful installation of the Java dependency. </em></p> 
</div> 

Next, Apache Cassandra was installed to serve as TheHive's database. The installation was complete by adding the Cassandra repository and installing the service, using the following commands:
```
wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
sudo apt update
sudo apt install cassandra
```
The ```systemctl status cassandra``` command was run to verify if Cassandra was successfully installed. 
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="814" height="332" alt="16-" src="https://github.com/user-attachments/assets/d715e6ac-ab9c-479c-9fd3-5bcd7edae21a" />
  <p><em>Figure 15: A screenshot of a successful Cassandra installation. </em></p> 
</div> 

After installation Cassandra needed to be configured to properly communicate with TheHive. This was done by modifying the ```cassandra.yaml``` configuration file located in the ```/etc/cassandra``` directory. 
```
nano /etc/cassandra/cassandra.yaml
```

Within the configuration file the ```listen_address```, was set as TheHive server's public IP address. 
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="803" height="254" alt="blurred-19 png" src="https://github.com/user-attachments/assets/177e2577-7cc3-4a35-a3ce-a2b50c272e7c" />
  <p><em>Figure 16: The listen_address parameter was modified.</em></p> 
</div> 

The same public IP address would be entered for both the ```rpc_address``` and the ```seeds``` parameters. 
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="801" height="193" alt="blurred-20 png" src="https://github.com/user-attachments/assets/72a9ca7b-8e64-45ae-8359-5219bee24fd4" />
  <p><em>Figure 17: The rpc_address parameter was modified.</em></p> 
</div> 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="752" height="218" alt="blurred-21 png" src="https://github.com/user-attachments/assets/27a01807-8374-4906-acc1-73cd80b18610" />
  <p><em>Figure 18: The seeds parameter was modified.</em></p> 
</div> 

Cassandra was then restarted with:
```
systemctl restart cassandra
```


The final prerequisite was Elasticsearch which, TheHive uses as a search and indexing engine. The installation was performed by adding the official Elasticsearch repository and installing it, using the following commands:
```
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
sudo apt update
sudo apt install elasticsearch
```
During setup, Elasticsearch failed to start due to heap memory issues, thus additional parameters were added by configuring a custom jvm.options file created in the ```/etc/elasticsearch/jvm.options.d``` directory.
The following entry was added in the jvm.options file, this limited Elasticsearch's heap memory allocation to 2GB.  
```
-Dlog4j2.formatMsgNoLookups=true
-Xms2g
-Xmx2g
```
The ```systemctl status elasticsearch``` command was run to verify if Elasticsearch was successfully installed and running.
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="814" height="332" alt="17" src="https://github.com/user-attachments/assets/7c23288d-e803-4be1-8bc6-bf10ee5f3177" />
  <p><em>Figure 19: A screenshot of a successful Elastic Search installation. </em></p> 
</div> 

Just like with Cassandra additional configuration was required so that TheHive could connect and index data properly, this was done by navigating to the ```/etc/elasticsearch``` directory and editing the ```elasticsearch.yml``` configuration file. 
```
nano /etc/elasticsearch/elasticsearch.yml
```
Within the configuration file the ```network.host```, was set as TheHive server's public IP address, ensuring Elasticsearch could listen for connections externally. 
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="780" height="130" alt="blurred-22 png" src="https://github.com/user-attachments/assets/5e667b11-7c91-468f-92c1-1beb50161bb7" />
  <p><em>Figure 20: The network.host parameter was modified. </em></p> 
</div> 

Within the configuration file the ```cluster.initial_master_nodes```, was configured with a single entry ```node-1```, since this project used only one node. 
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="805" height="124" alt="23" src="https://github.com/user-attachments/assets/1f0a9f06-5006-44f6-940b-8a517c1abc0c" />
  <p><em>Figure 21: The cluster.initial_master_nodes parameter was modified. </em></p> 
</div> 

Elasticsearch  was then restarted with:
```
systemctl restart elasticsearch
```

With all the pre-requisite installation and configuration complete the last step was to install TheHive. The package and its signatures were retrieved with the following commands:
```
wget -O /tmp/thehive_5.2.16-1_all.deb \
  https://thehive.download.strangebee.com/5.2/deb/thehive_5.2.16-1_all.deb
wget -O /tmp/thehive_5.2.16-1_all.deb.sha256 \
  https://thehive.download.strangebee.com/5.2/sha256/thehive_5.2.16-1_all.deb.sha256
wget -O /tmp/thehive_5.2.16-1_all.deb.asc \
  https://thehive.download.strangebee.com/5.2/asc/thehive_5.2.16-1_all.deb.asc
```
The download was then verified for integrity and authenticity using both a SHA-256 checksum and GPG signature verification:
```
sha256sum /tmp/thehive_5.2.16-1_all.deb

wget -O /tmp/strangebee.gpg \
  https://keys.download.strangebee.com/latest/gpg/strangebee.gpg
gpg --import /tmp/strangebee.gpg
gpg --verify /tmp/thehive_5.2.16-1_all.deb.asc \
             /tmp/thehive_5.2.16-1_all.deb
```
Finally, TheHive was installed with: 
```
apt-get install /tmp/thehive_5.2.16-1_all.deb
```
The ```systemctl status thehive``` command was run to verify if TheHive was successfully installed and running.
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="814" height="332" alt="18" src="https://github.com/user-attachments/assets/5dfbd509-4a98-43fa-b536-f9faf10d8b68" />
  <p><em>Figure 22: A screenshot of a successful TheHive installation. </em></p> 
</div> 

With everything successfully setup the final step was to configure TheHive itself. 
First, ownership of TheHive's ```/opt/thp/thehive``` installation directory  was set to the dedicated ```thehive``` user and group for security and proper service execution. 
```
chown -R thehive:thehive /opt/thp/thehive
```

Next, TheHive's ```application.conf``` configuration file was configured by modifying the ```hostname```, ```cluster.name```,```index.search.hostname```, and ```application.baseUrl``` parameters. 
```
nano /etc/thehive/application.conf
```
The ```cluster.name``` parameter would be mactched to the clustername in Cassandra's ```cassandra.yaml``` configuration file, which was called: ```SOC Project```. The remaining ```hostname```, ```index.search.hostname```, and ```application.baseUrl``` parameters would be set as TheHives public IP address. 
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="640" height="407" alt="blurred-24 png" src="https://github.com/user-attachments/assets/759b7db2-2d33-4c60-be83-3aa677c0306c" />
  <p><em>Figure 23: The hostname, cluster.name and index.search.hostname parameters were modified. </em></p> 
</div> 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="528" height="74" alt="blurred-25 png" src="https://github.com/user-attachments/assets/6f8072b1-07eb-4203-af7b-bd8028ab3161" />
  <p><em>Figure 24: The application.baseUrl parameter was modified. </em></p> 
</div> 

TheHive was then restarted with:
```
systemctl restart thehive
```

After ensuring that all three services were successfully running it was now possible to login into TheHive via web browser using TheHive's public IP and port ```9000```. 
```
http://<TheHive's Public IP>:9000
```
To login the TheHive's default credentials were used with the login being: ```admin@thehive.local``` and the password being: ```secret```.
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="2035" height="1262" alt="26-" src="https://github.com/user-attachments/assets/72994476-c158-4356-86f9-ccbffcd724e6" />  
  <p><em>Figure 25: A screenshot of the credentials used to login to TheHive. </em></p> 
</div> 

Once successfully logged in a new organization was created named ```AVILETI``` and two accounts were created: The first account  was an analyst account which would be used for investigating events. The second account was a service account, added specifically for Shuffle to authenticate via API, this account would later be used to automate case creation in TheHive.

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="939" height="421" alt="27" src="https://github.com/user-attachments/assets/8c1052f2-c02e-409c-b1d7-9fdd7368c081" />
  <p><em>Figure 26: A screenshot showing a newly created organization. </em></p> 
</div> 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="935" height="543" alt="28" src="https://github.com/user-attachments/assets/290f3249-f6a6-4d3f-b655-15c0ca292b5c" />
  <p><em>Figure 27: A screenshot showing a newly created analyst account. </em></p> 
</div> 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="934" height="511" alt="29" src="https://github.com/user-attachments/assets/8c9bcf01-3697-4e49-a94b-7bfd17068f4c" />
  <p><em>Figure 28: A screenshot showing a newly created service account.  </em></p> 
</div> 

## Creating Custom Alerts with Wazuh

































