# 🛡️ Intrusion Detection with Splunk (Real-World Scenario)

This document walks through a real-world scenario of detecting suspicious activity using Splunk and Sysmon logs.


## 🔍 Initial Investigation: Event Code Summary

We begin by identifying which EventCodes are present and how frequently they occur.

`index="main" sourcetype="WinEventLog:Sysmon" | stats count by EventCode`
![image](https://github.com/user-attachments/assets/d7c79c7f-0e81-442f-810d-840be22e273f)

#### Here is a link to all Sysmon v15.15 codes. List was updated as of July 23 2024
![Link](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) 

### 🧩 Step 1: Anomalous Parent-Child Process Trees

Unusual parent-child process relationships are often suspicious. Let's investigate:

`index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 | stats count by ParentImage, Image`

![image](https://github.com/user-attachments/assets/96dfb1c1-944a-4c81-b9ba-62d07f013bfe)

We then get a list of 5,427 events

Because of its extensiveness we will need to narrow the search. We can then focus on known problematic processes

"cmd.exe and powershell.exe"

`index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") | stats count by ParentImage, Image`

![image](https://github.com/user-attachments/assets/53c204bf-ff1b-4428-aea2-e53b1c80b0ca)

The results show us 628 results. Looking at the processes, we see notepad.exe **Parent** to powershell.exe **child**

*quite suspicious*

So not we narrow in on those events. 

`index="main" sourcetype="WinEventLog:Sysmon" EventCode=1 (Image="*cmd.exe" OR Image="*powershell.exe") ParentImage="C:\\Windows\\System32\\notepad.exe"`

![image](https://github.com/user-attachments/assets/c1f56504-cd9d-4baf-8e0a-cabf55772ee4)

Looking at the Commandline, we see a file is being we requested from an IP address called File.exe.
We will need to look into that IP and see if there are any other interactions.

`index="main" 10.0.0.229 | stats count by sourcetype`

![image](https://github.com/user-attachments/assets/ac47ef7a-b979-4864-854d-8e72b6b49922)

we get 95 events between 2 sourcetypes; WinEventLog:Sysmon and Linux:syslog

focusing on Linux
`index="main" 10.0.0.229 sourcetype="linux:syslog"`

![image](https://github.com/user-attachments/assets/b4ff4974-f4c7-4d12-a0d2-e085169858a1)

We conclude that the IP belongs to host = Waldo-Virtual-Machine

### Findings so far:

A linux System has started communicating with one of the internal machines. this communication includes downloading an Executable file using powershell and notepad.

#### Further investigation

`index="main" 10.0.0.229 sourcetype="WinEventLog:sysmon" | stats count by CommandLine`

We will not focus on the Sysmon data to see what information we can find

![image](https://github.com/user-attachments/assets/4552aff2-939b-4a2e-8fac-e2fb2ffd568a)

### These new findings show us specific files names being downloaded from a remote IP Looking into these files can help give more context to what the attack is attempting to do:
 - PsExec64.exe - an Executable file for running remote commands
 - SharpHound.exe - Used for data collection from the opensource tool BloodHound
 - File.exe - an unkown file, but from the context of the attack is a malicious file 
 - comsvcs.dll - this is a memory dump

#### From the information above: 
The attackers main goal is gathering data by remotely executing SharpHound.exe and memory dumping the data back to their Server
There also seems to be an infected Linux system trasmitting additional tools.

`index="main" 10.0.0.229 sourcetype="WinEventLog:sysmon" | stats count by CommandLine, host`

This query indicates 2 hosts are compromised. 
![image](https://github.com/user-attachments/assets/ef7844d7-d78c-43ba-bdbb-7bd55213dafa)

The second host shows DCsync was invoked. 
This could mean a DCSync attack was performed. Though more information will still need to be looked into. 
So we will narrow the results to look into a DCSync attack

`index="main" EventCode=4662 Access_Mask=0x100 Account_Name!=*$`

![image](https://github.com/user-attachments/assets/756cb8f2-bb13-4ae7-a8f0-cbb0aace5f73)

this query is very advanced and specific, I wouldn't have known to do this without HackTHeBox guiding me.
Here is the breakdown:

Event Code 4662 - AD object accessed. Not normally Triggered because it is normally disabled, 
and has to be deliberately enabled by the Domain Controller.

Access Mask 0x100 - requests control access typically needed for DCSync's high level permissions.

Account name checks where AD Objects are directly accessed by users instead of accounts. 
legitimat DCSync requests are normally performed by machine accounts or SYSTEM not users.

In order to find more information from the query, we will look at properties. This gives us 2 unique GUIDs.

![image](https://github.com/user-attachments/assets/5448084d-f4fb-48d6-b9d7-149d8fe5480b)

![image](https://github.com/user-attachments/assets/e820b438-eaa4-4b43-8f6f-7c1be4daa976)

#### Google is your friend here, after looking up the GUID's we find that one is for giving access to replicate secret domain data. That does not sound good and also verifies that a DCSync attack was executed. The level of access the user has indicates that this is a full compromise. Though how they got this level of access is still unknown. So that will need to be looked into.

The excercise indicates that we need to look into the possibility of LSASS dumping since this has been previosuly observed, 
which is used for credential harvesting. 

The Sysmon event code we will be utilizing is 10. This can provide us with data on process access or processes opening handles to other porcesses.

`index="main" EventCode=10 lsass | stats count by SourceImage`

Sorting by count gives us more comprehensible data to look at.

![image](https://github.com/user-attachments/assets/0826a080-3d7d-4eb8-8d22-1534f2ed1887)

It should be understood that frequent acctivity for a process is generally "normal" in an environment. What you need to be looking for are anomolies.

Processes that are either out of the ordinary to be run as well as infrequent processes that stand out.

notepad.exe is noticibly odd to produce Sysmon event code 10. as well as rundll32, because of its infrequency.

`index="main" EventCode=10 lsass SourceImage="C:\\Windows\\System32\\notepad.exe"`

![image](https://github.com/user-attachments/assets/c70a7dc9-bf6f-4b2c-a020-374917366d4d)

From these results we can look deeper into the potential credential dumping.

#### Lets breakdown the final results:
 - the results show a Credential Dumping attack was executed
 - It was initiated by Notepad.exe
 - the target process was LSASS, not normally accessed by Notepad, but used to dump passwords or hashes from memory
 - GrantedAccess: 0x1FFFFF indicates that full or nearly full access was given
 - call originated from within ntdll.dll to UNKNOWN, used often to evade detection.
 - User was Waldo and ran under the SYSTEM account

This attack now will need to be noted and an Alert should be set up to ensure this does not happen again.

In order to do this we will need to look into which call stacks contain UNKNOWN based on event codes.

`index="main" CallTrace="*UNKNOWN*" | stats count by EventCode`

From the results we only get Event code 10

![image](https://github.com/user-attachments/assets/4b284766-5fde-4ef6-a218-096922144597)

because of the number of results, we will need to group events by SourceImage and Count

`index="main" CallTrace="*UNKNOWN*" | stats count by SourceImage`

![image](https://github.com/user-attachments/assets/4e235127-e5e2-41b3-adf8-82103bc47914)

This shows us the false postivies and the legit results
All false positives are JITS, .Net is a JIT, Squirrel is a utility tied to electron. A Chromium based Browser and contains a JIT.

we still need to narrow down the malicious events and get rid of the false positives

`index="main" CallTrace="*UNKNOWN*" | where SourceImage!=TargetImage | stats count by SourceImage`

our results will need to get rid of C sharp as well, due to its JIT.

`index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* | where SourceImage!=TargetImage | stats count by SourceImage`

Next is WOW64, according to HackTHeBox:
 - WOW64 comprises regions of memory that are not backed by any specific file, a phenomenon we believe is linked to the Heaven's Gate mechanism, though we've yet to delve deep into this matter.

`index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* | where SourceImage!=TargetImage | stats count by SourceImage`

The next thing to exclude will be Explorer.exe, since it is the same as a wild card due to its frequent use.

`index="main" CallTrace="*UNKNOWN*" SourceImage!="*Microsoft.NET*" CallTrace!=*ni.dll* CallTrace!=*clr.dll* CallTrace!=*wow64* SourceImage!="C:\\Windows\\Explorer.EXE" | where SourceImage!=TargetImage | stats count by SourceImage`

This gives us a query that has narrowed down the results to only the actual attack. Though verifying the data is still a good practice.


## Practical Exercise

### 1. Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through an SPL search against all data the other process that dumped lsass. Enter its name as your answer. Answer format: _.exe

### 🖥️ What to Look For:

We are searching for a non-lsass process that interacted with LSASS in a suspicious way.

We should narrow results to those that show *lsass* as well as looking at the Parent Image, Image and CommandLine

The Command line should show us where an lsass dump is being performed, then we can assign that to the Image that performs the dump.

We know from the previous results that notepad.exe performed an lsass dump, so we can exclude that from the results.

`index="main" EventCode=10 lsass | stats count by SourceImage`

the results from the previously used query show us 2 infrequent SourceImages, notepad.exe and rundll32.


### 2. Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the method through which the other process dumped lsass. Enter the misused DLL's name as your answer. Answer format: _.dll

### 🖥️ What to Look For:

The **other** process is from the previous question. 
we will need to modify the last query to get more detailed results
We will remove the EventCode since we no longer need to specify that, and only need to look for lsass results
but will need to also change the stats section. 
We need to be able to see the Image and CommandLine, to see if lsassdump is being ran and through what process.

`index="main" *lsass* | stats count by Image, CommandLine`

from this result, we should be able to find the misused dll name.

### 3. Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through an SPL search against all data any suspicious loads of clr.dll that could indicate a C# injection/execute-assembly attack. Then, again through SPL searches, find if any of the suspicious processes that were returned in the first place were used to temporarily execute code. Enter its name as your answer. Answer format: _.exe

#### 🔍 Search for Suspicious clr.dll Loads
`index=* ImageLoaded="*clr.dll*" | stats count by Image, ImageLoaded`
this result will provide us with the processes that loaded clr.dll
We want to look specifically at the lower count results
![image](https://github.com/user-attachments/assets/7812135b-83e6-4b7f-90ba-95cb60d62a7d)

this will show us the anomolies.
Though, some of these are legitimate processes so we will need to exclude them.

### 🖥️ What to Look For

Unusual processes (e.g., rundll32.exe, notepad.exe, regsvr32.exe, etc.) that shouldn’t normally load .NET CLR

## 4. Navigate to http://[Target IP]:8000, open the "Search & Reporting" application,
   and find through SPL searches against all data the two IP addresses of the C2 callback server.
   Answer format: 10.0.0.1XX and 10.0.0.XX

🎯 Objective
Identify the two Command & Control (C2) callback IPs
In order to do this, we will need to concentrate our efforts on: 
 - Event Code 3 - for an established network connection
 - DestinationIp that is leading to the C2
 - Image - we know a few of the executables that were the main issue. So we will focus on those

`index="main" EventCode=3 DestinationIp=astrik*10.0.0.*astrik Image=SharpHound.exe OR rundll32.exe OR powershell.exe OR notepad.exe OR randomfile.exe
| stats count by DestinationIp, Image`

#### this command provides us with a good screenshot of the IPs and what commands are being run.
but we still cant really narrow down the answer. So we will also add DestinationPort and RuleName to see what exactly is happening on what port
We will also narrow down the results even more to only Image results that we should be worried about. 
The way I did it was a more round about way, but it gives good contect on what I Included using **OR** 

`index="main" EventCode=3 DestinationIp=*10.0.0.* Image=SharpHound.exe OR rundll32.exe OR powershell.exe OR notepad.exe OR randomfile.exe
| stats count by DestinationIp, Image, DestinationPort, RuleName`

![image](https://github.com/user-attachments/assets/01ff4100-3ad0-4fdf-9e23-c71b04b0b5d6)

#### these results show us a much more precise picture of what is happening. We see a few key things going on.

1. port 80 is highly exploitable.
2. notepad is using a technique it definitely should not be doing.
3. the word "masquerading" by a "randomfile" is very telling
4. rundll32 is being ran by 2 specific IPs only


## 5. Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, 
and find through SPL searches against all data **the port** that one of the two C2 callback server IPs used to connect to one of the compromised machines.

`index="main" EventCode=3 DestinationIp=10.0.0.** OR 10.0.0.*** | stats count by _time DestinationIp, Image, DestinationPort, RuleName`

#### In order to find the port used, we need to narrow down our search to the specific IPs from the previous question
Here is how to narrow down your query:
1. Specify the destination C2 IPs
2. You will need to use stats
3. you need to see the destination IP associated to the Destionation port
4. look through Image and RuleName for clues on processes
5. The time is the most important to see where this all started

The timeline is the most crutial to understand where this attack started

