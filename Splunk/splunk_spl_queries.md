// 1. Detect Malicious Extension Sideloading via Developer Mode

| tstats `security_content_summariesonly` min(_time) as firstTime max(_time) as lastTime 
  from datamodel=Endpoint.Processes 
  where Processes.process_name="chrome.exe" Processes.process="*--load-extension*"
  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process

| `drop_dm_object_name(Processes)`
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`

// 2. Detect Malicious Extension Payload Staging (.crx drops via Sysmon)
// Searches only for Sysmon operational data for Event Code 11 to identify files created on a system.[1]
search source="xmlwineventlog:microsoft-windows-sysmon/operational" EventCode=11 (file_name="*.crx" OR file_path="*\\AppData\\Local\\Google\\Chrome\\User Data\\*\\Extensions\\*")

| search file_path="*fnmihdojmnkclgjpcoonokmkhjpjechg*" OR file_path="*inhcgfpbfdjbjogdfjbclgolkmhnooop*" OR file_path="*kkodiihpgodmdankclfibbiphjkfdenh*"
| table _time, host, user, file_name, file_path

// 3. Detect Suspicious Authentication Anomalies Post-Exfiltration
// Uses Event Code 4624 to determine outliers of normal login, filtering by Logon Type.[5]
search sourcetype="wineventlog:security" EventCode=4624 

| eventstats avg("_time") as avg stdev("_time") as stdev 
| eval lowerBound=(avg - stdev*2) 
| where _time < lowerBound OR Logon_Type IN (3, 10) 
| stats count by TargetUserName, IpAddress, Logon_Type, WorkstationName
| where NOT match(IpAddress, "^10\.|^192\.168\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.")