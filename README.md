# Malicious-Script Lab
In this lab, I simulated the download and execution of a malicious script on a Windows 10 system and referecing the NIST 800-61 guideline, to the extent of the lab, I was able to set up alerts to detect, investigate it, and isolate the machine. The malicious file was download from Atomic Red Team; an organization that publishes malicious files that allow for you to simulate cyber attacks. In this case, the script ends by opening the calculator app.

## Tools Utilized
- Wireshark
- Powershell
- Microsoft Defender (KQL)

## Step 1: Setting up the Alert in Microsoft Defender
I created the following the detection rule in Defender using the following query:
`
DeviceProcessEvents
| where DeviceName == "rojas-mde"
| where FileName =~ "AutoIt3.exe"
| where ProcessCommandLine has_any (".au3", "calc.au3")
| where FolderPath has_any ("Users", "Temp", "Downloads")
`



