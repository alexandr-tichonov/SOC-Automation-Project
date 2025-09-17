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
  
  From the options presented, a Windows operating system was selected, with the server address being the Wazuh managers public IP address, the agent iteself was named as "Agent-1". 
  
  
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
  <img width="935" height="543" alt="28" src="https://github.com/user-attachments/assets/6e5066b0-f62e-42d2-be0b-da53a29fc34d" />
  <p><em> Figure 27: A screenshot showing a newly created analyst account. </em></p> 
</div> 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="934" height="511" alt="29" src="https://github.com/user-attachments/assets/8c9bcf01-3697-4e49-a94b-7bfd17068f4c" />
  <p><em>Figure 28: A screenshot showing a newly created service account.  </em></p> 
</div> 

## Creating Custom Alerts with Wazuh
By default, Wazuh only records events that trigger a rule or alert. To capture all raw logs (including those that do not match any existing rules), Wazuh was reconfigured on the Wazuh manager machine. 

This was done by editing the Wazuh managers ```ossec.conf``` configuration file, and modifying the ```<logall>``` and ```<logall_json>``` parameters under the ```<ossec_config>``` block to ```yes```. 
```
nano /var/ossec/etc/ossec.conf
```
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="744" height="313" alt="30" src="https://github.com/user-attachments/assets/f1c1f201-8b2d-478d-9db4-15f7826d03ef" />
  <p><em>Figure 29: logall and logall_json parameters were modified.  </em></p> 
</div>
The Wazuh manager was then restarted by running: 

```
systemctl restart wazuh-manager.service
```
Once Wazuh was configured to log all events, the raw data began appearing in the ```/var/ossec/logs/archives``` directory as archive logs. Unfortunatley Wazuh, by default, does not ingest archive logs simply leaving them stored for future reference. 

To enable ingestion of archived logs, the Filebeat configuration file ```filebeat.yml``` was updated, by modifying the ```archives:``` ```enabled:``` parameter to ```true```.
```
nano /etc/filebeat/filebeat.yml
```
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="722" height="278" alt="32" src="https://github.com/user-attachments/assets/09569f4d-6e6b-4e3c-a889-647e2174919a" />
  <p><em>Figure 30: The archives: enabled: parameter was modified. </em></p> 
</div>

The Filebeat service was then restarted to implement the change. 


With the Filebeat now ingesting the archive logs, a new **index pattern** was created in the Wazuh web interface to visualize this data. The index pattern was defined as:
```wazuh-archives-*```.

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1198" height="464" alt="33" src="https://github.com/user-attachments/assets/bb3732f3-1c94-4a67-9ac1-948c7409a0dc" />
  <p><em>Figure 31: A screenshot showing the previously available index patterns. </em></p> 
</div>

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1200" height="536" alt="34" src="https://github.com/user-attachments/assets/90ebd742-c4a4-4019-a4f7-40af59d411fe" />
  <p><em>Figure 32: A screenshot showing the index pattern definition. </em></p> 
</div>

Mimikatz is a well-known post-exploitation tool commonly used by attackers to extract credentials from Windows systems. Due to its prevelance in real-world intrusions, the goal of this project was to detect the execution of Mimikatz immidiatley upon launch, even when the Binary was renamed to evede simple signature based detections. 

To validate the detection capablities of the newly configured Wazuh SIEM Mimikatz was first executed under its original filename ```mimikatz.exe```. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="625" height="220" alt="35" src="https://github.com/user-attachments/assets/0dc7d29a-53dc-4974-83c2-101dbfdc6421" />
  <p><em>Figure 33: A screenshot showing the execution of mimikatz.exe </em></p> 
</div>

By searching the newly crated ```wazuh-archives-*``` index in the Wazuh web interface, two recorded events related to Mimikatz execution were observed, thus confirming that Wazuh, via Sysmon event collection, was able to capture the execution of Mimikatz. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1600" height="619" alt="blurred-36 png" src="https://github.com/user-attachments/assets/63497dd9-3513-41b3-9c77-f39f43ef4419" />
  <p><em>Figure 34: A screenshot of two Mimikatz related events being displayed on the Wazuh dashboard. </em></p> 
</div>

By closely analyzing the events generated when Mimikatz was executed, it was possible to identify a reliable field for detection which was the ```originalFileName``` field. This field retains the executable's true internal name ```mimikatz.exe``, even if the file itself is renamed by the attacker. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1451" height="680" alt="37" src="https://github.com/user-attachments/assets/160d4bff-6f58-4b8f-85f1-16eceaa4d0eb" />
  <p><em>Figure 35: A screenshot showing the orginalFileName parameter being displayed within an alert. </em></p> 
</div>

By utilizing the ```originalFileName``` field, a custom Wazuh rule could be created via the web interface by navigating to **Server management → Rules → Manage rules files → Custom rules** and editing the ```local_rules.xml``` configuration file.  

From here, a new rule can be added by pasting the following XML configuration:

```
<rule id="100002" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)\\mimikatz\.exe</field>
  <description>Mimikatz was detected!</description>
  <mitre>
    <id>T1003</id>
  </mitre>
</rule>
```

Where the severity ```level``` parameter was set to ```15```, which forces the detection to be treated as a critical alert, and the ```<mitre>``` ```<id>``` was set to ```T1003```, which ties the event to  credential dumping.

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="892" height="535" alt="38" src="https://github.com/user-attachments/assets/8f4f6a75-1d1a-431d-8e84-955ccdb4981b" />
  <p><em>Figure 36: A screenshot showing the entry made in the local_rules.xml configuration file. </em></p> 
</div>

To test the effectiveness of the custom rule, ```mimikatz.exe``` was renamed to ```just a basic program.exe``` and executed on the test machine. Despite the name change, the detection rule leveraged the ```originalFileName``` parameter and triggered a critical alert.

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="670" height="149" alt="39" src="https://github.com/user-attachments/assets/2e0d0c92-1f37-4a15-a6cb-b0c116688cd4" />
  <p><em>Figure 37: A screenshot showing the renamed Mimikatz executable </em></p> 
</div>

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1600" height="731" alt="blurred-40 png" src="https://github.com/user-attachments/assets/9a9fd28c-c35a-4ade-8723-6c94321db3af" />
  <p><em>Figure 38: A screenshot showing the event created after Mimikatz was executed. </em></p> 
</div>

## SOC Automation with Shuffle
The culmination of this project revolves around Shuffle, which is an open-source Security Orchestration, Automation and Response (SOAR) platform, that allows analysts to create automated workflows. In this case Shuffle was used to enrich events sent from Wazuh with virus total, which would then be sent to TheHive for further case management. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1418" height="242" alt="42" src="https://github.com/user-attachments/assets/06a508f7-923c-414f-b36d-2647dc01bb31" />
  <p><em>Figure 39: A screenshot showing the creation of a new workflow. </em></p> 
</div>

A new workflow was created in Shuffle starting with a Webhook node called ```Wazuh_Alerts```. This webhook serves as the entry point through which Wazuh will forward its alerts. 


<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1328" height="805" alt="43" src="https://github.com/user-attachments/assets/b918aa10-6f0a-4d10-8f43-a19fd22bde39" />
  <p><em>Figure 40: A screenshot showing a webhook node being added to a workflow.  </em></p> 
</div>

In order for Wazuh to send events to Shuffle, the generated Webhook URI was added to the Wazuh Manager's ```/var/ossec/etc/ossec.conf``` configuration file under a new ```<integration>``` tag. 
The following entry was made in the ```ossec.conf``` file:
```
<integration>
  <name>shuffle</name>
  <hook_url> <Webhook URL> </hook_url>
  <rule_id>100002</rule_id>
  <alert_format>json</alert_format>
</integration>
```
As a preliminary test the ```<rule_id>``` parameter was set to rule id ```100002```, which is a custom rule that was previously created to log Mimikatz events. This was done to initially simplfy the necessary automation required.  
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1042" height="253" alt="41" src="https://github.com/user-attachments/assets/22665404-4585-4efc-a565-05ac18559bce" />
  <p><em>Figure 41: A screenshot showing an entry being made in the ossec.conf configuration file.  </em></p> 
</div>

Wazuh manager was then restarted by running:
```
systemctl restart wazuh-manager.service
```

The Webhook URI was then started and Mimikatz was executed on the Windows virtual machine to generate a Mimikatz related alert. Shortly after runnning the workflow Shuffle successfully recieved the alert from Wazuh which was now displayed via its web interface. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="884" height="466" alt="44" src="https://github.com/user-attachments/assets/2fc37cce-9906-4a24-b8e5-86972da846f0" />
  <p><em>Figure 42: A screenshot showing a Mimikatz related alert being displayed via Shuffle's web interface.  </em></p> 
</div>

Inspecting the raw alert data inside Shuffle revealed several useful fields, including a ```hashes``` parameter. The **SHA256 hash** looked like a promising field that can later be used for enrichment via **VirusTotal**. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="779" height="237" alt="45" src="https://github.com/user-attachments/assets/75f664a3-56b9-4845-9261-9772af22af22" />
  <p><em>Figure 43: A screenshot of additional Mimikatz related event parameters. </em></p> 
</div>

**Enrichment with Virus Total**: When an alert is recieved, the raw data displayed is often not enough to immidiatley understand the threat. Enrichment adds context through the correlation of data with external threat intelligence sources, thus helping analysts differentiate false positives from malicious indicators.   

For this project, the use of the ```hashes``` parameter would be ideal for reputation checks on VirusTotal as the **SHA256** hash serves as a unique identifier for executables and remains unchanged regardless if a file is renamed or not.  

In order to successfully parse the **SHA256** parameter from the ```hashes``` field the ```Change Me``` node was modified in the Shuffle workflow. The ```Find actions``` field was configured as a ```Regex capture group```, with the ```Input data``` argument being: ```$exec.text.win.eventdata.hashes```. 

Finally the following entry was added in the corresponding ```Regex``` field: 
```
SHA256=([0-9A-Fa-f]{64})
```

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1146" height="757" alt="47" src="https://github.com/user-attachments/assets/e62445d2-789c-4374-b763-e0a440406fcf" />
  <p><em>Figure 44: A screenshot of the newly modified SHA256-Regex node.  </em></p> 
</div>

After rerunning the workflow and executing mimikatz on the Windows virtual machine the SHA256 hash value was successfully parsed, (as shown in Shuffles output). 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="898" height="538" alt="48" src="https://github.com/user-attachments/assets/bd9c0da1-5e47-4023-98b3-e53c234d1fa8" />
  <p><em>Figure 45: A successfully parsed SHA256 hash value. </em></p> 
</div>

The VirusTotal node was then added to Shuffle's workflow with the ```Find actions``` field being set to the ```Get a hash report``` parameter. Additionally the ```$sha256-regex.group_0.#``` execution argument was added in the ```Id``` field to interpret the newly parsed SHA256 value.  

Finally Shuffle would authenticate to VirusTotal using an API key which is given after successfully creating a VirusTotal account.

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1478" height="854" alt="49" src="https://github.com/user-attachments/assets/3e585fa7-14f0-404b-bf73-5e7c28240f2a" />
  <p><em>Figure 46: A screenshot of a newly configured VirusTotal node. </em></p> 
</div>

With VirusTotal fully integrated, the Shuffle workflow was rerun. The SHA256 hash extracted from the Mimikatz alert was successfully sent to VirusTotal, which would return an enriched response. This response would later be used for case management with TheHive. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="830" height="355" alt="50" src="https://github.com/user-attachments/assets/0c1bfec5-fca5-46b4-867d-b29c44c7df2c" />
  <p><em>Figure 47: A screenshot of the response sent from VirusTotal. </em></p> 
</div>

**Integrating TheHive into Shuffle**: Once VirusTotal enrichment was successful, the next step was to create a case in TheHive. This was done by adding a "TheHive5" node in the Shuffle workflow and configuring its Advanced Body section to pass relevant details from the Wazuh alert and VirusTotal results. Additionally authentication between Shuffle and TheHive was handled using an API key created for the dedicated service account shuffle@test.com.

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1600" height="872" alt="52" src="https://github.com/user-attachments/assets/eba1a607-0dda-44c4-a5c7-8eeb7f6241e5" />
  <p><em>Figure 48: A screenshot of the newly configured TheHive node. </em></p> 
</div>

To ensure as much relevant detail was sent to TheHive as possible the following custom ```json``` entry was added in the ```Advanced``` ```Body``` field.
```
{
  "title": "Alert: $exec.text.win.eventdata.description on $exec.text.win.system.computer", 
  "description": "Detected by $exec.all_fields.full_log.win.system.providerName at $exec.text.win.eventdata.utcTime\n\nHost: $exec.text.win.system.computer ($exec.all_fields.agent.ip)\nUser: $exec.all_fields.data.win.eventdata.user\nOS: Windows\n\nOriginal File: $exec.text.win.eventdata.originalFileName\nCommand Line: $exec.text.win.eventdata.commandLine\nParent Command Line: $exec.all_fields.data.win.eventdata.parentCommandLine\nParent PID: $exec.all_fields.full_log.win.eventdata.parentProcessId\nHashes: $exec.text.win.eventdata.hashes", 
  "flag": false, 
  "pap": 2, 
  "source": "Wazuh", 
  "sourceRef": "Rule:$exec.rule_id-$exec.text.win.system.computer-$exec.all_fields.data.win.eventdata.user-$exec.text.win.eventdata.utcTime", 
  "status": "New", 
  "summary": "$exec.text.win.eventdata.description detected on $exec.text.win.system.computer by $exec.all_fields.data.win.eventdata.user", 
  "tags": [
    "Rule:$exec.rule_id", 
    "Host:$exec.text.win.system.computer", 
    "User:$exec.all_fields.data.win.eventdata.user", 
    "Provider:$exec.all_fields.full_log.win.system.providerName"
  ], 
  "tlp": 2, 
  "type": "Internal"
}

```
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="845" height="393" alt="53" src="https://github.com/user-attachments/assets/7caba716-33e6-49a9-81a4-dbb9046f9235" />
  <p><em>Figure 49: An example json entry used for TheHive. </em></p> 
</div>

The workflow was then rerun, and Wazuh alerts enriched with VirusTotal data were automatically forwarded to TheHive.

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="848" height="521" alt="54" src="https://github.com/user-attachments/assets/83790d7e-c1ca-4754-adb8-92490698ec09" />
  <p><em>Figure 50: An screenshot of the response sent back once the workflow was rerun. </em></p> 
</div>

Logging in with the previously configured ```avileti@test.com``` analyst account, a new alert could be seen in TheHive with details being automatically populated from Wazuh and VirusTotal. 

This confirmed that Shuffle was successfully automating the process of receiving Wazuh alerts, enriching them via VirusTotal, and creating detailed cases inside TheHive for investigation.

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1158" height="481" alt="55" src="https://github.com/user-attachments/assets/017c34ed-07d7-43ad-8258-861e5c65a1d7" />
  <p><em>Figure 51: An example Mimikatz alert that was automatically created in TheHive. </em></p> 
</div>


**Integrating email notifications**: 
The final step was to create an email notification system where the analyst can be immidiatley notified of any suspicious alerts. To do so an email node would be dragged and connected directly after the VirusTotal enrichment. The ```Recipient```, ```Subject```, and ```Body``` fields were customized to pass along relevant information regarding the alert. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1127" height="789" alt="blurred-57 png" src="https://github.com/user-attachments/assets/9c590c00-dec4-4033-8f13-a080234027d4" />
  <p><em>Figure 52: A screenshot of the newly configured Email node. </em></p> 
</div>

The email would also instruct the analyst to login into TheHive in order to conduct further investigation. To test the system the Shuffle workflow was rerun and email notification was successfully recieved. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="709" height="473" alt="56" src="https://github.com/user-attachments/assets/39734cbe-2a7f-4259-979d-6c5f44147df9" />
  <p><em>Figure 53: An example email notification recieved by the analyst. </em></p> 
</div>

**Phase 1 Summary**: With Phase 1 of this project finalized and concluded, a complete end-to-end alerting pipeline would be built.  **Wazuh** would successfully detect the execution of **Mimikatz**, even when the binary was renamed. The alert would then be enriched externally with **VirusTotal**, and would be forwarded to **TheHive** as a structured case. Finally an email notification would be sent to notify the analyst of the suspicious event prompting them to login to **TheHive** for further investigation.    

## Technical Implementation Walkthrough (Phase 2)
This section will be used to explain the exact steps taken to successfully set up and configure the second phase of this project.

## Setting up the Wazuh Agent on Linux
Similar to what was done during phase 1 a Wazuh agent would be configured on the previously setup Ubuntu machine hosted in the cloud. The decision to switch from Windows to Linux was intentional, as Wazuh’s active response is much more consistent on Linux, especially for automated actions such as blocking malicious IP addresses.  

When configuring the Wazuh agent the Linux ```DEB amd64``` package would be selected with the server address being the Wazuh managers public IP address, the agent iteself was named as "Agent-3". 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1750" height="1244" alt="blurred-59 png" src="https://github.com/user-attachments/assets/58c4a968-c9bf-4efb-96f3-1c9ac8c7d6f3" />
  <p><em>Figure 54: A screenshot of the options configured during agent setup. </em></p> 
</div>

The provided command would then be executed in the terminal in order to successfully setup the Wazuh agent. 
```
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.12.0-1_amd64.deb && sudo WAZUH_MANAGER='<Public IP Address>' WAZUH_AGENT_NAME='Agent-3' dpkg -i ./wazuh-agent_4.12.0-1_amd64.deb
```
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="956" height="440" alt="blurred-60 png" src="https://github.com/user-attachments/assets/e3804181-f56e-4512-81ad-92017cfc0bf2" />
  <p><em>Figure 55: A screenshot of the installation command being run in the terminal. </em></p> 
</div>

The agents installation was verified by going to the Wazuh dashboard and obeserving what agents are currently online. We can see that the Linux agent has been successfully setup. 
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1734" height="247" alt="blurred-61 png" src="https://github.com/user-attachments/assets/66860dd4-ff70-4fee-bd4f-510fea45b6c5" />
  <p><em>Figure 56: A screenshot of the Linux agent being operational. </em></p> 
</div>

## Configuring Active Response for Wazuh
To enable active blocking of malicious IP addresses, the **Wazuh Active Response** was configured in the Wazuh manager.

This was done by editing the previously mentioned ```ossec.conf``` configuration file located in the ```/var/ossec/etc/``` directory, with the following ```<active-response>``` entry added:
```
<active-response>
  <command>firewall-drop</command>
  <location>local</location>
  <level>11</level>
  <timeout>no</timeout>
</active-response>
```
The ```<timeout>``` was set to ```no```, which indicates a permanent block of the IP address, this was chosen soley out of preference, and can be set to a specific timeout length. 
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="890" height="324" alt="62" src="https://github.com/user-attachments/assets/76df0d1c-c817-4a40-a081-88be963a015e" />
  <p><em>Figure 57: A screenshot of the active response entry added in the ossec.conf configuration file. </em></p> 
</div>

**Forwarding SSH Alerts to Shuffle**: The idea for the second phase of this project was to block suspicious login attempts via ssh. To do so Wazuh had to successfully send failed ssh login events directly to Shuffle via webhook URI. 

Thus the first step was to reconfigure the previously added ```<integration>```block, inside the```ossec.conf``` configuration file, located within the ```/var/ossec/etc``` directory. The ```<rule_id>``` parameter would then be modified from ```100002```, and was instead set to ```5760```. 

Wazuh's ```rule_id 5760``` specifically targets the log message: ```sshd: authenitcation failiure```, thus triggering an alert whenever a failed ssh login occurs. The following entry was thus added to the ```ossec.conf``` configuration file:

```
<integration>
  <name>shuffle</name>
  <hook_url> <Webhook URL> </hook_url>
  <rule_id>5760</rule_id>
  <alert_format>json</alert_format>
</integration>
```

The changes to the ```ossec.conf``` file were then appropriately saved and the Wazuh manager was restarted. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="772" height="249" alt="64" src="https://github.com/user-attachments/assets/abff6fa1-05d8-492e-912c-e70d53c94196" />
  <p><em>Figure 58: A screenshot of the integration block entry added in the ossec.conf configuration file. </em></p> 
</div>

**Reconfiguring VirusTotal for Shuffle**: Before an automated response is taken against a suspicious SSH login attempt, it is important to first verify the reputation of the source IP address. This ensures that defensive actions, such as active blocking, are taken only when there is enough supporting intelligence. 

To achieve this, the existing VirusTotal node in Shuffle would be reconfigured with the ```Find actions``` field being modified to: ```Get an IP address report```. The ```$exec.all_fields.data.srcip``` argument would then be passed into the ```Ip``` field of the node, which will dynamically extract the source IP address from the Wazuh alert that triggered rule_id **5760**. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1142" height="768" alt="65" src="https://github.com/user-attachments/assets/fb7b7837-f13b-4770-b36e-bb3547979002" />
  <p><em>Figure 59: The VirusTotal node reconfigured to query IP reputation. </em></p> 
</div>


**Configuring the Get-API node in Shuffle** For Shuffle to instruct Wazuh to take automated action, it first needs to authenticate securely with the Wazuh API. To retrieve the token, an HTTP node was added to the Shuffle workflow. The node was renamed to ```Get-API```and the Find actions field was set to ```curl```, which was configured with the Wazuh API user credentials that were obtained during Wazuh's inital installation. 

In order for Shuffle to successfully obtain the token the following command entry would be made in the ```Statement``` field: 
```
curl -u <username>:<password> -k -X GET "https://<Wazuh-IP>:55000/security/user/authenticate?raw=true"
```
Where ```<Wazuh-IP>``` is the Wazuh managers public IP address. 

<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1123" height="571" alt="blurred-63 png(2)" src="https://github.com/user-attachments/assets/89627535-d0a1-4b33-8e96-20cdbd60d84c" />
  <p><em>Figure 60: A screenshot of the newly configured Get-API node. </em></p> 
</div>

**Configuring the PUT Node for Active Response**: During this nearly final stage of the workflow, the idea was to instruct Wazuh to take automated action against an IP address. To do this, another HTTP node was added to the Shuffle workflow and renamed to ```PUT```. The ```Find actions field``` of the node was set to make a ```PUT``` request, with the following URI being provided: 
```
https://<Wazuh-Manager-IP>:55000/active-response?agents_list=003
```
Here, ```<Wazuh-Manager-IP>``` represents the public IP of the Wazuh manager, while ```003``` corresponds to the ID of the previously configured Wazuh agent on the Ubuntu machine.

For API authentication, the following headers were added:
```
{
  "Authorization": "Bearer $get-api",
  "Content-Type": "application/json"
}
```

Where the ```$get-api``` value was dynamically obtained from the previously configured Get-API node, ensuring that Shuffle could securely interact with the Wazuh API.  

Before committing to a dynamic entry for the body field, a small preliminary test was conducted with a static entry, where an attempt was made to activley drop traffic from Google's public DNS (```8.8.8.8```).

Thus the following static entry would be made in the ```Body``` field of the request:
```
{
  "command": "firewall-drop",
  "arguments": [
    "8.8.8.8"
  ],
  "alert": {
    "data": {
      "srcip": "8.8.8.8"
    }
  }
}
```
The workflow structure was thus arranged in the following configuration:
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1338" height="788" alt="blurred-67 png" src="https://github.com/user-attachments/assets/1f287039-4e06-4f52-b956-d39e18f3fd28" />
  <p><em>Figure 61: A screenshot of the newly configured PUT node. </em></p> 
</div>

The workflow was then saved and rerun, and the following response was sent by the Wazuh API:
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="873" height="390" alt="blurred-68 png" src="https://github.com/user-attachments/assets/965cc53f-2b36-4d23-a78d-6b4feaf78acc" />
  <p><em>Figure 62: A screenshot of the Wazuh API responding successfully. </em></p> 
</div>

To validate whether the IP address ```8.8.8.8``` was in fact blocked, an SSH session was opened into the Ubuntu machine and the following command was executed in the terminal:
```
iptables -L INPUT -n | grep 8.8.8.8
```
The results confirmed that the active response had succeeded, with 8.8.8.8 listed as a dropped address.
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="696" height="171" alt="69" src="https://github.com/user-attachments/assets/cc4f1d37-a6dd-411e-a0f6-815ceb85b5f0" />
  <p><em>Figure 63: A screenshot of the 8.8.8.8 Ip address being successfully dropped.  </em></p> 
</div>

With the preliminary test complete, the static entry was replaced with a dynamic one, replacing the hardcoded ```8.8.8.8``` address with the ```$exec.all_fields.data.srcip``` argument. The following final json entry would thus be made in the ```Body``` field of the ```PUT``` node.
```
{
  "command": "firewall-drop",
  "arguments": ["$exec.all_fields.data.srcip"],
  "alert": {
    "data": {
      "srcip": "$exec.all_fields.data.srcip"
    }
  }
}
```
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="714" height="216" alt="70" src="https://github.com/user-attachments/assets/f002be85-93d4-43f6-be20-3555d0b36df8" />
  <p><em>Figure 64: A screenshot of the final entry that was made in the body field.  </em></p> 
</div>

**Adding Analyst Confirmation via User Input**: To avoid automatically blocking SSH login attempts for legitimate users, a User Input node was added to the workflow. This node would send an email notification to the analyst prompting them to decide whether to block the suspicious IP address. 

To implement this the User Input node would be dragged into the Shuffle workflow. The ```Information``` and ```Input options``` fields were then modified, with the final configuration being setup as follows: 
<div align="center" style="border: 2px solid #ccc; padding: 4px;"> 
  <img width="1331" height="682" alt="blurred-71 png(1)" src="https://github.com/user-attachments/assets/88375530-d5b8-4510-b518-6a9331f50ab6" />
  <p><em>Figure 65: A screenshot of a successfully configured User Input node.  </em></p> 
</div>





























































