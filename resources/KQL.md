
//Go to  https://aka.ms/lademo in your browser (you will need a account on Azure AD)
//Explore the available tables listed in the tab on the left side of the screen.
//In the query editor, enter the following query and select the **Run** button.  You should see the query results in the bottom window.

//KQL
SecurityEvent
| take 10
//

//Next to the first record, select the **>** to expand the information for the row.

// The following statement demonstrates searching across all tables and columns for records within the 
// query time range display in the query window. In the Query Window before running this script change the
// **Time range** to "Last hour". Enter the following statement and select **Run**: 

//KQL
search "err"
| take 10
//

// >**Warning:** Make sure you change back the Time range to "Last 24 hours" for the next scripts.

// The following statement demonstrates searching across tables listed with the "in" clause for records 
// within the query time range display in the query window. In the Query Window. Enter the following 
// statement and select **Run**: 

//KQL
search in (SecurityEvent,SecurityAlert,A*) "err"
| take 10
//

// The following statements demonstrates filter using the where operator. In the Query Window. Enter the 
// following statement and select **Run**: 
// >**Note:** You should "run" after entering the query from each code block below.

//KQL
SecurityEvent
| where TimeGenerated > ago(1h)
//

//KQL
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == "4624"
//

//KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == 4624
| where AccountType =~ "user"
//

//KQL
SecurityEvent 
| where TimeGenerated > ago(1h) and EventID in (4624, 4625)
//

// The following statement demonstrates the use of the let statement to declare variables. In the Query
// Window. Enter the following statement and select **Run**: 

//KQL
 let timeOffset = 7d;
 let discardEventId = 4688;
 SecurityEvent
 | where TimeGenerated > ago(timeOffset*2) and TimeGenerated < ago(timeOffset)
 | where EventID != discardEventId
//

// The following statement demonstrates the use of the let statement to declare a dynamic list. In the 
// Query Window enter the following statement and select **Run**: 

//KQL
let suspiciousAccounts = datatable(account: string) [
    @"\administrator", 
    @"NT AUTHORITY\SYSTEM"
];
SecurityEvent | where Account in (suspiciousAccounts)
| take 10
//

// The following statement demonstrates the use of the "let" statement to declare a dynamic table. In the 
// Query Window. Enter the following statement and select **Run**: 

//KQL
let LowActivityAccounts =
    SecurityEvent 
    | summarize cnt = count() by Account 
    | where cnt < 1000;
LowActivityAccounts | where Account contains "sql"
//

// The following statement demonstrates creating fields using the extend operator In the Query Window.
// Enter the following statement and select **Run**: 

//KQL
SecurityEvent
| where ProcessName != "" and  ProcessName != "-" and Process != "" and Process != "-"
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
| project ProcessName, Process, StartDir
| take 10
//

// The following statement demonstrates sorting results using the order by operator. In the Query Window. 
// Enter the following statement and select **Run**: 

//KQL
SecurityEvent
| where ProcessName !in ("", "-") and Process !in ("", "-")
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
| project ProcessName, Process, StartDir
| order by ProcessName desc, Process asc
| take 100
//


//KQL
SecurityEvent
| where ProcessName != "" and Process != ""
| extend StartDir =  substring(ProcessName,0, string_size(ProcessName)-string_size(Process))
| order by StartDir desc, Process asc
| project-away ProcessName
| take 10
//

// In this task, you will build KQL statements to prepare data.
// The following statement demonstrates the count function. In the Query Window. Enter the following 
// statement and select **Run**: 

//KQL
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == "4688"
| summarize total=  count() by Process, Computer
| take 100
//


// The following statement demonstrates the dcount function. In the Query Window. Enter the following
// statement and select **Run**: 

//KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize dcount(IpAddress)
//

// The following statement is a rule to detect Invalid password failures across multiple applications for 
// the same account. In the Query Window enter the following statement and select **Run**: 

//KQL
let timeframe = 14d;
let threshold = 1;
SigninLogs
| where TimeGenerated >= ago(timeframe)
| where ResultDescription has "Invalid password"
| summarize applicationCount = dcount(AppDisplayName) by UserPrincipalName, IPAddress
| where applicationCount >= threshold
//

// The following statement demonstrates the arg_max function.
// The following statement will return the most current row from the SecurityEvent table for the computer 
// SQL10.NA.contosohotels.com.  The * in the arg_max function requests all columns for the row. In the 
// Query Window. Enter the following statement and select **Run**: 

//KQL
SecurityEvent 
| where Computer == "SQL10.na.contosohotels.com"
| summarize arg_max(TimeGenerated,*) by Computer
//

// The following statement demonstrates the arg_min function.
// In this statement, the oldest SecurityEvent for the computer SQL10.NA.contosohotels.com will be 
// returned as the result set. In the Query Window. Enter the following statement and select **Run**: 

//KQL
SecurityEvent 
| where Computer == "SQL10.na.contosohotels.com"
| summarize arg_min(TimeGenerated,*) by Computer
//

// The following statements demonstrate the importance of understanding results based on the order of the 
// pipe "|". In the Query Window. Enter the following queries and run each separately: 

// **Query 1** will have Accounts for which the last activity was a login. The SecurityEvent table will 
// first be summarized and return the most current row for each Account.  Then only rows with EventID
// equals 4624 (login) will be returned.

//KQL
SecurityEvent
| summarize arg_max(TimeGenerated, *) by Account
| where EventID == "4624"
//

// **Query 2** will have the most recent login for Accounts that have logged in.  The SecurityEvent table 
// will be filtered to only include EventID = 4624. Then these results will be summarized for the most 
// current login row by Account.

//KQL
SecurityEvent
| where EventID == "4624"
| summarize arg_max(TimeGenerated, *) by Account
//

// >**Note:**  You can also review the "Total CPU" and "Data used for processed query" by selecting the 
// bar "Completed" and compare the data between both statements.

// The following statement demonstrates the make_list function.

// The make_list function returns a dynamic (JSON) array of all the values of Expression in the group. 
// This KQL query will first filter the EventID with the where operator.  Next, for each Computer, the 
// results are a JSON array of Accounts. The resulting JSON array will include duplicate accounts.

// In the Query Window. Enter the following statement and select **Run**: 

//KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == "4624"
| summarize make_list(Account) by Computer
//

// The following statement demonstrates the make_set function.
// The make_set function returns a dynamic (JSON) array containing *distinct* values that Expression 
// takes in the group. This KQL query will first filter the EventID with the where operator.  Next, for 
// each Computer, the results are a JSON array of unique Accounts. In the Query Window. Enter the 
// following statement and select **Run**: 

//KQL
SecurityEvent
| where TimeGenerated > ago(1h)
| where EventID == "4624"
| summarize make_set(Account) by Computer
//


// In this task, you will use generate visualizations with KQL statements.

// The following statement demonstrates the render function visualizing results with a barchart. In the 
// Query Window. Enter the following statement and select **Run**: 

//KQL
SecurityEvent 
| where TimeGenerated > ago(1h)
| summarize count() by Account
| render barchart
//

// The following statement demonstrates the render function visualizing results with a time series.
// The bin() function rounds values down to an integer multiple of the given bin size.  Used frequently 
// in combination with summarize by .... If you have a scattered set of values, the values are grouped 
// into a smaller set of specific values.  Combining the generated time series and pipe to a render 
// operator with a type of timechart provides a time series visualization. In the Query Window. Enter the 
// following statement and select **Run**: 

//KQL
SecurityEvent 
| where TimeGenerated > ago(1h)
| summarize count() by bin(TimeGenerated, 1m) 
| render timechart
//


// In this task, you will build multi-table KQL statements.
// The following statement demonstrates the union operator that takes two or more tables and returns the 
// rows of all of them. Understanding how results are passed and impacted with the pipe character is 
// essential. In the Query Window. Enter the following statements and select **Run** for each separately 
// to see the results: 

// **Query 1** will return all rows of SecurityEvent and all rows of SigninLogs.

//KQL
SecurityEvent 
| union SigninLogs  
| take 100
//

// **Query 2** will return one row and column, which is the count of all rows of SecurityEvent and all 
// rows of SigninLogs.

//KQL
SecurityEvent 
| union SigninLogs  
| summarize count() 
//

// **Query 3** will return all 10 rows of SecurityEvent and one row for SigninLogs.  The row for SigninLogs
// will have the count of the SigninLogs rows.

//KQL
SecurityEvent | take 10
| union (SigninLogs | summarize count()| project count_)
//

// The following statement demonstrates the union operator support for wildcards to union multiple 
// tables. In the Query Window. Enter the following statement and select **Run**: 

//KQL
union Security* 
| summarize count() by Type
//

// The following statement demonstrates the join operator, which merges the rows of two tables to form a 
// new table by matching the specified columns' values from each table. In the Query Window. Enter the 
// following statement and select **Run**: 

//KQL
SecurityEvent 
| where EventID == "4624" 
| summarize LogOnCount=count() by EventID, Account 
| project LogOnCount, Account 
| join kind = inner (
SecurityEvent 
| where EventID == "4634" 
| summarize LogOffCount=count() by EventID, Account 
| project LogOffCount, Account 
) on Account
//

// The first table specified in the join is considered the Left table.  The table after the join keyword 
// is the right table.  When working with columns from the tables, the $left.Column name and $right.
// Column name is to distinguish which tables column are referenced. 


// In this task, you will work with structured and unstructured string fields with KQL statements.

// The following statement demonstrates the extract function.  Extract gets a match for a regular expression from a text string. You have the option to convert the extracted substring to the indicated type. In the Query Window. Enter the following statement and select **Run**: 

//KQL
print extract("x=([0-9.]+)", 1, "hello x=45.6|wo") == "45.6"
//

// The following statements use the extract function to pull out the Account Name from the Account field 
// of the SecurityEvent table. In the Query Window. Enter the following statement and select **Run**: 

//KQL
SecurityEvent
| where EventID == 4672 and AccountType == 'User'
| extend Account_Name = extract(@"^(.*\\)?([^@]*)(@.*)?$", 2, tolower(Account))
| project Account, Account_Name

//

// The following statement demonstrates the parse function. Parse evaluates a string expression and 
// parses its value into one or more calculated columns. The computed columns will have nulls for 
// unsuccessfully parsed strings.

//KQL
let Traces = datatable(EventText:string)
[
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=23, lockTime=02/17/2016 08:40:01, releaseTime=02/17/2016 08:40:01, previousLockTime=02/17/2016 08:39:01)",
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=15, lockTime=02/17/2016 08:40:00, releaseTime=02/17/2016 08:40:00, previousLockTime=02/17/2016 08:39:00)",
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=20, lockTime=02/17/2016 08:40:01, releaseTime=02/17/2016 08:40:01, previousLockTime=02/17/2016 08:39:01)",
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=22, lockTime=02/17/2016 08:41:01, releaseTime=02/17/2016 08:41:00, previousLockTime=02/17/2016 08:40:01)",
"Event: NotifySliceRelease (resourceName=PipelineScheduler, totalSlices=27, sliceNumber=16, lockTime=02/17/2016 08:41:00, releaseTime=02/17/2016 08:41:00, previousLockTime=02/17/2016 08:40:00)"
];
Traces  
| parse EventText with * "resourceName=" resourceName ", totalSlices=" totalSlices:long * "sliceNumber=" sliceNumber:long * "lockTime=" lockTime ", releaseTime=" releaseTime:date "," * "previousLockTime=" previousLockTime:date ")" *  
| project resourceName, totalSlices, sliceNumber, lockTime, releaseTime, previousLockTime
//

// The following statement demonstrates working with dynamic fields, which are special since they can 
// take on any value of other data types. In this example, The DeviceDetail field from the SigninLogs 
// table is of type dynamic. In the Query Window enter the following statement and select Run: 


//KQL
SigninLogs 
| extend OS = DeviceDetail.operatingSystem
//

// The following example shows how to break out packed fields for SigninLogs. In the Query Window enter 
// the following statement and select Run:


//KQL
SigninLogs 
| where TimeGenerated >= ago(1d)
| extend OS = DeviceDetail.operatingSystem, Browser = DeviceDetail.browser
| extend ConditionalAccessPol0Name = tostring(ConditionalAccessPolicies[0].displayName), ConditionalAccessPol0Result = tostring(ConditionalAccessPolicies[0].result)
| extend ConditionalAccessPol1Name = tostring(ConditionalAccessPolicies[1].displayName), ConditionalAccessPol1Result = tostring(ConditionalAccessPolicies[1].result)
| extend ConditionalAccessPol2Name = tostring(ConditionalAccessPolicies[2].displayName), ConditionalAccessPol2Result = tostring(ConditionalAccessPolicies[2].result)
| extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Status.additionalDetails)
| extend State = tostring(LocationDetails.state), City = tostring(LocationDetails.city)
| extend Date = startofday(TimeGenerated), Hour = datetime_part("Hour", TimeGenerated)
| summarize count() by Date, Identity, UserDisplayName, UserPrincipalName, IPAddress, ResultType, ResultDescription, StatusCode, StatusDetails, ConditionalAccessPol0Name, ConditionalAccessPol0Result, ConditionalAccessPol1Name, ConditionalAccessPol1Result, ConditionalAccessPol2Name, ConditionalAccessPol2Result, Location, State, City
| sort by Date
//

// The following statement demonstrates functions to manipulate JSON stored in string fields. Many logs 
// submit data in JSON format, which requires you to know how to transform JSON data to queryable fields. 

// In the Query Window. Enter the following statements individually and select **Run**: 

//KQL
 SigninLogs
| extend Location =  todynamic(LocationDetails)
| extend City =  Location.city
| extend City2 = Location["city"]
| project Location, City, City2
| take 1
//

// The mv-expand operator expands multi-value dynamic arrays or property bags into multiple records.


//KQL
 SigninLogs
| extend Location = todynamic(LocationDetails)
| project LocationDetails
//

//KQL
 SigninLogs
| mv-expand Location = todynamic(LocationDetails)
//

// The mv-apply operator applies a subquery to each record and returns the union of the results of all 
// subqueries.

//KQL
SigninLogs
| mv-apply Location = todynamic(LocationDetails) on 
( where Location.countryOrRegion == "US")
//

// Example – Parse JSON

//KQL
SigninLogs
| extend device_details = parse_json(DeviceDetail)
| project device_details.browser, device_details.operatingSystem, device_details.trustType
//

// Example – Parse CSV

//KQL
print result_multi_record=parse_csv('record1,a,b,c\nrecord2,x,y,z’)
//

//KQL
print result_multi_record=parse_csv('record1,a,b,c\nrecord2,x,y,z')
| project result_multi_record[0], result_multi_record[1] //first value , second value
//KQL

// Example – Parse XML

//KQL
SecurityEvent
| where EventData != ""
| take 1
| extend event_data = parse_xml(EventData)
| project event_data, event_data.UserData.RuleAndFileData.RuleName, event_data.UserData.RuleAndFileData.PolicyName, event_data["UserData"]["RuleAndFileData"]["PolicyName"]
//KQL


// Chart the rate of process creation on all domain controllers.

//KQL
SecurityEvent
| where Computer startswith "DC"
| where EventID == "4688" | summarize count() by Computer, bin(TimeGenerated, 1h) 
| render timechart
//



// Find how many times each process ran per computer

//KQL
SecurityEvent | summarize by Activity // Let’s find the event that includes process names

SecurityEvent | where EventID == "4688" | limit 10 
	// find the relevant field, in this case "Process" 

SecurityEvent
| where EventID == "4688"
| summarize count() by Process, Computer
//


///Load external data 
///Azrue Data Cetner IP Ranges and list them by servcie (e.g. Azure Front Door)
//Read: https://learn.microsoft.com/en-us/azure/virtual-network/service-tags-overview
externaldata (
    values: dynamic
)
[
    "https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20250505.json"
]
with (
    format = 'multijson'
)
| mv-expand values
| extend service = tostring(values.name)
| extend addressPrefixes = values.properties.addressPrefixes
| mv-expand addressPrefixes
| project service, ip = tostring(addressPrefixes)
| summarize make_list(ip) by service

//Check IP belogs to Azure and list matching services
let ip_to_check = "13.64.151.161"; //example
externaldata(values: dynamic)
[
  "https://download.microsoft.com/download/7/1/d/71d86715-5596-4529-9b13-da13a5de5b63/ServiceTags_Public_20250505.json"
]
with(format='multijson')
| mv-expand values
| extend serviceName = tostring(values.name)
| extend prefixes = values.properties.addressPrefixes
| mv-expand prefix = prefixes
| extend ip = tostring(prefix)
| extend isMatch = ipv4_is_in_range(ip_to_check, ip)
| where isMatch == true
| summarize match=any(isMatch) by serviceName
