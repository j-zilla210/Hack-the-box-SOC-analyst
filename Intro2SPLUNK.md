![image](https://github.com/user-attachments/assets/b9efb3c7-75e7-43c9-b5c5-1a79fd01cdc1)

## Splunk Enterprise through HackTheBox Lab

### Search and Reporting
From within SPLUNK we have the ability to manage data.

We will first be looking at the Search & reporting section specifically to look for incidents.
![image](https://github.com/user-attachments/assets/ed3b2161-23b0-46d5-8147-e5d0d5599134)
In order to understand how to use SPLUNK's search feature we have to learn Splunk Processing Language(SPL)
It has over a hundred commands, functions, arguments, and clauses. All of which you dont need to know by heart
but it would be remise to not grasp most.


To start, we may want to get familiar with what data we are using
![image](https://github.com/user-attachments/assets/f0d46bb3-4368-4077-b453-8b98bc89a43c)

 
 `| eventcount summarize=false index=* | table index `

Letsbreak down the above command
 - "eventcount" counts events in all indexes
 - "summarize=false index=*" is used to display counts for each index separately
 - "table index"  is used to present the data in tabular form.

If we run this command we get 3 options:
 - history
 - main
 - summary

By clicking on each and selecting "view events" we will find that only "main" has any events available

lets move to the objectives

## The first objective
![image](https://github.com/user-attachments/assets/1389045b-e32c-4cd3-8671-013e14362555)
I am tasked with using an SPL search against all data the account name with the highest amount of Kerberos authentication ticket requests

### Breaking down the SPL search
We now need to look at what our search should look like
 - ALL data, so we need to ensure the time frame used is "all time"
 - What will the index source be
   - `index="main"` 
 - Find what event ID is for Kerberos Authentication Ticket requests
    - after doing a quick search, the Event Id is 4768
    - `| EventCode=4768`
 - Then we would need to breakdown the search by Account Name
 - `| stats count by Account_name`
 - and sort the Account names by the number of the most event codes
 - `| sort -count`

`index="main" EventCode=4768 
| stats count by Account_Name
| sort -count`

![image](https://github.com/user-attachments/assets/0fc57c5d-cdb4-495d-ae1b-3c481418fd5c)



## Second Objective
Another search using an SPL search against all 4624 events the count of distinct computers accessed by the account name SYSTEM.

 - event code 4624 signifies a successful logon to a Windows system

### Breaking down the SPL search needed:
 - Search against all 4624 event | so we will specify EventCode=4624
 - The count of distinct computers | looking for computers
 - ACCESSED by the account name SYSTEM | looking for account name SYSTEM

So now we create our SPL search
`index="main" EventCode=4624`
 **Output:**
![image](https://github.com/user-attachments/assets/0819c329-23e5-4f04-9d76-319665156bbc)

 - We specified the EventCode, but we have to specify the Account_name SYSTEM
`index=* EventCode=4624 Account_Name=SYSTEM`

![image](https://github.com/user-attachments/assets/9a7acec3-807c-4b4b-a956-ccf544b10194)

 - Now we are provided a more focused view within the event code 4624 and the account name SYSTEM
But still need to find the *count of distinct computers*
If you look in the Fields section under "Interesting fields" you will see the *ComputerName* option
![image](https://github.com/user-attachments/assets/f83954b3-57ae-4738-93c5-098691eb7a89)

 - clicking on that option opens a sub-menu that shows us the 10 distinct computer names that SYSTEM accessed

### Another option would be a more direct search:

`index="main" EventCode=4624 Account_Name=SYSTEM 
| stats dc(ComputerName) as distinct_computers`

## Third Objective
Find through an SPL search against all 4624 events the account name that made the most login attempts within a span of 10 minutes

### Breaking down the SPL search needed:

 - Search against all 4624 event | so we will specify EventCode=4624 again
 - We need to find an Account name
 - With the most login attemps within a span of 10 minutes

`index=* EventCode=4624
| stats count, range(_time) as time_range by Account_Name
| where time_range <= 600`
