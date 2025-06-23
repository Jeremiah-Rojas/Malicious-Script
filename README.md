# Malicious-Script Lab
In this lab, I simulated the download and execution of a malicious script on a Windows 10 system and referecing the NIST 800-61 guideline, to the extent of the lab, I was able to set up alerts to detect, investigate it, and isolate the machine. The malicious file was download from Atomic Red Team; an organization that publishes malicious files that allow for you to simulate cyber attacks. In this case, the script ends by opening the calculator app.

## Tools Utilized
- Wireshark
- Powershell
- Microsoft Defender (KQL)

## Step 1: Setting up the Alert in Microsoft Defender
Rule 1:
I created a detection rule in Defender that would detect the existence of a file on the system named `AutoIt3.exe` which in this case is the script executor. The rule also checks if any commands run on the system that contain the values `.au3` or `calc.au3`, then the alert is triggered.
I created the detection rule using the following query:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-mde"
| where FileName =~ "AutoIt3.exe"
| where ProcessCommandLine has_any (".au3", "calc.au3")
| where FolderPath has_any ("Users", "Temp", "Downloads")
```
Rule 2:
This detection rule is triggered when `AutoIt.exe` launches `calc.exe`. The way I know to search with these parameters is because these processes are common given the attack scenario.
I created the detection rule using the following query:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-mde"
| where InitiatingProcessFileName =~ "AutoIt3.exe"
| where FileName =~ "calc.exe"
```
Rule 3:
This rule was designed to trigger an alert when Powershell is used to download content from the internet; this is done using the `Invoke-WebRequest`.
I created the detection rule using the following query:
```kql
DeviceProcessEvents
| where DeviceName == "rojas-mde"
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-WebRequest", "wget", "curl")
| where ProcessCommandLine has "autoit" "getfile.pl"
```
Rule 4:
The last rule triggers an alert when Powershell is being used to install `AutoIt.exe`. Powershell is not a common method of installing programs like these in normal day-to-day activities therefore this activity is considered suspicious.
I created the detection rule using the following query:
```kql
DeviceFileEvents
| where DeviceName == "rojas-mde"
| where FileName has "autoit" and FileName endswith ".exe"
| where InitiatingProcessFileName =~ "powershell.exe"
```
## Step 2: Running the Attack (Steps taken by the Attacker/Victim)
This series of commands would have been taken by the victim or attacker depending on the circumstances in the real-world.

This downloads the full library of Atomic Red simulated attacks into the VM, including the script that will be run. 
```powershell
git clone https://github.com/redcanaryco/atomic-red-team.git
```
This command moves the user to the folder where the scripts are loaded.
```powershell
cd C:\Users\ceh2025\atomic-red-team
```
This command makes sure that the atomic script is being pulled from the correct folder (Atomics) that was created when the user cloned the Atomic Red database of attacks.
```powershell
$env:PathToAtomicsFolder = "C:\Users\YourUser\atomic-red-team\atomics\"
```
This prepares the VM for running the attacks by downloading the right module to do so. “-AllowClobber” also allows the user to override any existing modules that could get in the way.
```powershell
Install-Module -Name Invoke-AtomicRedTeam -Force -AllowClobber
```
This pulls up the needed module to run the script for the current Powershell session. The user will see it install in powershell.
```powershell
Import-Module Invoke-AtomicRedTeam
```
This prepares the VM for the attacks by creating the right permissions so that no security controls interfere.
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
```
This command downloads and installs all the prerequisites needed to run the script.
```powershell
Invoke-AtomicTest T1059 -GetPrereqs -PathToAtomicsFolder "C:\Users\YourUser\atomic-red-team\atomics\"
```
Runs and detonates the malicious script in the VM. The calculator should launch after running this; in a real-world scenario, the end result would be much more concerning.
```powershell
Invoke-AtomicTest T1059 -PathToAtomicsFolder "C:\Users\YourUser\atomic-red-team\atomics\"
```
![image](https://github.com/user-attachments/assets/6db2f87a-4951-4020-bde6-366ef5f1e45f)

## Step 3: Analyze the Indicators of Compromise
Using Microsoft Defender, I was able to view the steps the malicious attacker took to facilitate the attack. Within this page, is it also useful to make note of the timestamps.
![image](https://github.com/user-attachments/assets/05ecd3d7-301a-467b-a9dc-5a1e7745c945)

According to the NIST 800-61 guidelines, there are certain tasks necessary to perform in order to determine if the alert is a true or false positive.
