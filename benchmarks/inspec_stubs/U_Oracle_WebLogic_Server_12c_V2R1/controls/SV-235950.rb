control 'SV-235950' do
  title 'Oracle WebLogic must provide the ability to write specified audit record content to an audit log server.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application specific events, success/fail indications, filenames involved, access control or flow control rules invoked. 

Centralized management of audit records and logs provides for efficiency in maintenance and management of records, as well as the backup and archiving of those records. Application servers and their related components are required to be capable of writing logs to centralized audit log servers.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'JDBC Data Sources' 
3. From the list of data sources, select the one named 'opss-audit-DBDS', which connects to the IAU_APPEND schema of the audit database. Note the value in the 'JNDI name' field
4. To verify, select 'Configuration' tab -> 'Connection Pool' tab 
5. Ensure the 'URL' and 'Properties' fields contain the correct connection values for the IAU_APPEND schema
6. To test, select 'Monitoring' tab, select a server from the list and click 'Test Data Source'. Ensure test was successful. Repeat for each server in the list 
7. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Security Provider Configuration' 
8. Beneath 'Audit Service' section, click 'Configure' button 
9. Ensure 'Data Source JNDI Name' value matches the JNDI Name value from data source in step 3 above
10. Repeat steps 2-6 for data source named 'wls-wldf-storeDS' and WLS schema

If the location for audit data is not an audit log server, this is a finding."
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
  tag check_id: 'C-39169r628626_chk'
  tag severity: 'medium'
  tag gid: 'V-235950'
  tag rid: 'SV-235950r628628_rule'
  tag stig_id: 'WBLC-02-000081'
  tag gtitle: 'SRG-APP-000515-AS-000203'
  tag fix_id: 'F-39132r628627_fix'
  tag 'documentable'
  tag legacy: ['SV-70503', 'V-56249']
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
