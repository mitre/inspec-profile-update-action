control 'SV-235930' do
  title 'Oracle WebLogic must employ automated mechanisms to facilitate the monitoring and control of remote access methods.'
  desc 'Remote network access is accomplished by leveraging common communication protocols and establishing a remote connection. 

Application servers provide remote management access and need to provide the ability to facilitate the monitoring and control of remote user sessions. This includes the capability to directly trigger actions based on user activity or pass information to a separate application or entity that can then perform automated tasks based on the information. 

Examples of automated mechanisms include but are not limited to: automated monitoring of log activity associated with remote access or process monitoring tools. 

The application server must employ mechanisms that allow for monitoring and control of web-based and command line-based administrative remote sessions.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'JDBC Data Sources' 
3. From the list of data sources, select the one named 'opss-audit-DBDS', which connects to the IAU_APPEND schema of the audit database. Note the value in the 'JNDI name' field.
4. To verify, select 'Configuration' tab -> 'Connection Pool' tab 
5. Ensure the 'URL' and 'Properties' fields contain the correct connection values for the IAU_APPEND schema
6. To test, select 'Monitoring' tab, select a server from the list and click 'Test Data Source'. Ensure test was successful. Repeat for each server in the list. 
7. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Security Provider Configuration' 
8. Beneath 'Audit Service' section, click 'Configure' button 
9. Ensure 'Data Source JNDI Name' value matches the JNDI Name value from data source in step 3 above
10. Repeat steps 2-6 for data source named 'wls-wldf-storeDS' and WLS schema

If the data is not being stored for access by an external monitoring tool, this is a finding."
  desc 'fix', "1. Access AC 
2. From 'Domain Structure', select 'Services' -> 'Data Sources' 
3. Utilize 'Change Center' to create a new change session 
4. Click 'New' data source to create a new data source for the audit data store using schema IAU_APPEND
5. Enter database details and JNDI name, click through wizard 
6. Select all servers and clusters available as targets to deploy this data source to 
7. Finish creating the data source and record the JNDI name 
8. Access EM 
9. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Security Provider Configuration' 
10. Beneath 'Audit Service' section, click 'Configure' button 
11. Set the values for the IAU_APPEND schema and save configuration
12. Repeat steps 2-7 for data source named 'wls-wldf-storeDS' and WLS schema"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39149r628566_chk'
  tag severity: 'medium'
  tag gid: 'V-235930'
  tag rid: 'SV-235930r628568_rule'
  tag stig_id: 'WBLC-01-000011'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag fix_id: 'F-39112r628567_fix'
  tag 'documentable'
  tag legacy: ['SV-70463', 'V-56209']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
