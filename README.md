# Malicious-Script Lab
In this lab, I simulated the download and execution of a malicious script on a Windows 10 system and referecing the NIST 800-61 guideline, to the extent of the lab, I was able to set up alerts to detect, investigate it, and isolate the machine. The malicious file was download from Atomic Red Team; an organization that publishes malicious files that allow for you to simulate cyber attacks. In this case, the script ends by opening the calculator app.

## Tools Utilized
- Wireshark
- Powershell
- Microsoft Defender (KQL)

## Step 1: Setting up the Alert in Microsoft Defender
I created a detection rule in Defender that would detect the existence of a file on the system named "AutoIt3.exe" which in this case is the script executor. The rule also checks if any commands run on the system that contain the values ".au3" or "calc.au3," then the alert is triggered.
I created the detection rule using the following query:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-mde"
| where FileName =~ "AutoIt3.exe"
| where ProcessCommandLine has_any (".au3", "calc.au3")
| where FolderPath has_any ("Users", "Temp", "Downloads")
```
## Step 2: Setting up the Alert in Microsoft Defender
I created a detection rule in Defender that would detect the existence of a file on the system named "AutoIt3.exe" which in this case is the script executor. The rule also checks if any commands run on the system that contain the values ".au3" or "calc.au3," then the alert is triggered.
I created the detection rule using the following query:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-mde"
| where InitiatingProcessFileName =~ "AutoIt3.exe"
| where FileName =~ "calc.exe"
```


