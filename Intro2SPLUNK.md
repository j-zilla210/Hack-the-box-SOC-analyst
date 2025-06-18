![image](https://github.com/user-attachments/assets/b9efb3c7-75e7-43c9-b5c5-1a79fd01cdc1)

## Splunk Enterprise through HackTheBox Lab

### Search and Reporting
From within Splunk, we can manage security-related data across its lifecycle. This includes ingesting logs from firewalls, IDS/IPS, endpoints, and authentication systems. We can parse and normalize this data for consistent analysis, extract fields for threat hunting, and build correlation searches to detect suspicious activity. Splunk also supports real-time alerts, security dashboards, and reports to monitor for potential threats. Role-based access controls help ensure that sensitive data is only visible to authorized users, supporting both security operations and compliance needs.


We will first be looking at the Search & reporting section specifically to look for incidents.

![image](https://github.com/user-attachments/assets/ed3b2161-23b0-46d5-8147-e5d0d5599134)

> In order to understand how to use SPLUNK's search feature we have to learn Splunk Processing Language(SPL)
It has over a hundred commands, functions, arguments, and clauses. All of which you dont need to know by heart
but it would be remise to not grasp most.

### Here are some SPL basics that helped it click for me:

---

### 🔹 Commands
Commands are the foundation of your search. Each command gives you a different toolset to work with.  
You can link commands using **pipes** (`|`) — this passes the result of one command into the next.  
Combining commands helps narrow your search with varying levels of detail and accuracy.

---

### 🔹 Boolean Operators
Boolean operators like `AND`, `OR`, and `NOT` help define more precise search logic.  
They’re great for including or excluding results to make your query more targeted.

---

### 🔹 Source, Sourcetype, Host, EventCode
Knowing where your data is coming from is key.  
Using fields like `source`, `sourcetype`, `host`, or `EventCode` helps limit results to relevant data, making your searches more efficient and meaningful.

---

### 🔹 Time Range & `_time` Field
Understanding time is essential in Splunk. Most logs are time-based, and almost every search relies on the `_time` field.  
You can set a time range manually in the UI or filter within your SPL using commands like:

`| where _time >= relative_time(now(), "-1h")`

### 🔹 `stats` Field
The stats command is one of the most powerful in SPL.
It lets you count, average, group, and summarize your data in meaningful ways

`| stats count by Account_Name`


### To start, we may want to get familiar with what data we are using

> `| eventcount summarize=false index=* | table index `

Lets break down the above command
 - `eventcount` counts events in all indexes
 - `summarize=false index=*` is used to display counts for each index separately
 - `table index`  is used to present the data in tabular form.
   
![image](https://github.com/user-attachments/assets/f0d46bb3-4368-4077-b453-8b98bc89a43c)

If we run this command we get 3 options:
 - `history`
 - `main`
 - `summary`

By clicking on each and selecting "view events" we will find that only `main` has any events available

> lets move to the objectives

## First objective
![image](https://github.com/user-attachments/assets/1389045b-e32c-4cd3-8671-013e14362555)
> Use an SPL search across all data to find the account name with the highest number of Kerberos authentication ticket requests.

### 🔍 Breaking down the SPL search

 - The search must include all time, so adjust your time picker accordingly.

 - Start with the relevant index:
   
`index="main"`

 - Kerberos ticket requests use EventCode 4768:
   
`EventCode=4768`

 - Group the results by account name:
   
`| stats count by Account_Name`

 - Sort by the number of events, descending:
   
`| sort -count`

### ✅ Final SPL:

`index="main" EventCode=4768
| stats count by Account_Name 
| sort -count`

![image](https://github.com/user-attachments/assets/0fc57c5d-cdb4-495d-ae1b-3c481418fd5c)

---

## Second Objective

![image](https://github.com/user-attachments/assets/bece796a-4fb9-478a-bbec-7c313ab62c17)

> Use an SPL search against all 4624 events to count the distinct computers accessed by the SYSTEM account.

*event code 4624 signifies a successful logon to a Windows system*

### 🔍 Breaking down the SPL search needed:
 - Filter for EventCode 4624:
   
  `EventCode=4624`

 - Target only the SYSTEM account:
   
 `Account_Name=SYSTEM`

 - Look for distinct computers accessed — the `ComputerName` field shows which machines were accessed.

### ✅ SPL Progression
1. Basic Search:
   
`index="main" EventCode=4624`
 
 **Output:**
![image](https://github.com/user-attachments/assets/0819c329-23e5-4f04-9d76-319665156bbc)

2. Add the account Filter:
   
`index=* EventCode=4624 Account_Name=SYSTEM`

![image](https://github.com/user-attachments/assets/9a7acec3-807c-4b4b-a956-ccf544b10194)

3. Look under Interesting Fields for `ComputerName`. Clicking it may show how many distinct computers SYSTEM accessed:

![image](https://github.com/user-attachments/assets/f83954b3-57ae-4738-93c5-098691eb7a89)


### ✅ Direct SPL Search

`index="main" EventCode=4624 Account_Name=SYSTEM 
| stats dc(ComputerName) as distinct_computers`


## Third Objective
![image](https://github.com/user-attachments/assets/f7444007-0e02-41bd-92ff-c5f0cd777d23)

> Use an SPL search across all 4624 events to find the account with the most login attempts within a 10-minute window.

### 🔍 Breaking down the SPL search needed:

 - Filter for EventCode 4624:
   
  `EventCode=4624`

 - The Stats command
   
  `| stats`
 - we need to cound logins per account
   
  `by Account_name`
 - Use range(_time) to calculate the duration (in seconds) between the first and last login for each account.
   
  `range(_time) as time_range`
 - Filter for accounts `where` that range is `less than or equal to` (boolean) 10 minutes (600 seconds):
   
  `| where time_range <= 600`


## In conclusion

This concludes some of the more basic search functionality that I have grasped.
I look forward to continue my training with SPLUNK and other SIEM software.
