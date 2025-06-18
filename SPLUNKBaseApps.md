## Adding an app to Splunk

![image](https://github.com/user-attachments/assets/718b7759-5756-4da3-a6c4-79674752845e)

In the next excersize I added an app to Splunk using Splunkbase

After creating an account, I downloaded *Sysmon App for Splunk*
![image](https://github.com/user-attachments/assets/d8a124ee-36ea-4fe9-ae24-8ebb15d79a09)


> From the main page you go to settings | "Install app from File" |  Browse for the file and Upload

![image](https://github.com/user-attachments/assets/f7c16795-67c8-40be-a584-3947f46a99be)

![image](https://github.com/user-attachments/assets/c5f34bca-afea-4686-9cb3-b2f9bc58b5b5)


> Splunk must Restart to complete the update
![image](https://github.com/user-attachments/assets/6a7e9381-65fe-4232-9df1-45d8edeb4bc5)


We will need to adjust the `macros` in `Settings` to ensure events are loaded.
 - Select `Search macros`
 - specify ther app option as `sysmon app for Splunk`
 - select `sysmon` option in drop down
 - adjust definition to:

   `index="main" sourcetype="WinEventLog:Sysmon"`
- save
- you should see the banner below

![image](https://github.com/user-attachments/assets/80730bb8-26d7-474a-92b6-beb7593e2333)


### Question one
![image](https://github.com/user-attachments/assets/b767b709-7ef9-4296-b9f5-5ebbd93dd1e0)

#### Task: Access the Sysmon App for Splunk and navigate to the "Reports" tab.
 - Locate the report titled "Net - net view" and review the associated SPL search.
 - Identify and fix any issues with the search to return the expected results.
 - Once corrected, determine the full executed command captured in the logs.
 - Submit the full command in the format: net view /Domain:_.local

Here is the SPL search for Net - net view

![image](https://github.com/user-attachments/assets/7d8b6b40-be80-4908-991d-f50aa4b7a422)

currently it does not produce any results
I need to find CommandLine results with *net view* in them
I attempted to add `EventCode=1` after `sysmon` but this didn't change the results
There was also a space too much between net and view
I added * on both sides of net view to expand the possibilities of the results
![image](https://github.com/user-attachments/assets/f1b277d9-f760-4389-b7c3-c4dae68023d5)

After this, I still do not have any results. I decided to remove `process=net.exe`
This provided 2 results
![image](https://github.com/user-attachments/assets/c47ca779-9d2c-486d-addf-95080c23c53c)

This part of the excersice tells me that even though there are set search queries, they will not automatically work
out of the box.

### Question rwo
![image](https://github.com/user-attachments/assets/0ddd8e59-4aa1-4465-bdad-26b7185c4d9f)

#### Task: Open the Sysmon App for Splunk and navigate to the "Network Activity" tab.
 - Under "Network Connections", inspect and fix the SPL search if needed.
 - Identify how many network connections were initiated by SharpHound.exe.
 - The final answer should be the total count of these connections.
#### Here is the initial search query
![image](https://github.com/user-attachments/assets/a4df03b8-d652-4f8c-80fb-e51e101b8a47)

it is big and scary, but we just need to break it down so that we can get what we need.

 - `EventCode=3` this is Sysmon’s network connection event
 - `Image="$imgsel$"` this is the tokenized input for the dashboard (where we will put "*SharpHound.exe")
 - `eval` `stats` `fields` all Formatting needed to present data
 - `stats` is a bit messy for me so I will narrow it down to only whats needed to answer the question
   `| stats count by Image` this will specify that we only want the count of the resulting image option
 - `field` will need to maintain the full options to give us to present the data

   


Result
![image](https://github.com/user-attachments/assets/62e673f8-1833-44d8-b631-85567677d544)

