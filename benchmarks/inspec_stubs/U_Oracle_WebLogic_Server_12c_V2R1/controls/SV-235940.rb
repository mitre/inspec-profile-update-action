control 'SV-235940' do
  title 'Oracle WebLogic must compile audit records from multiple components within the system into a system-wide (logical or physical) audit trail that is time-correlated to within an organization-defined level of tolerance.'
  desc 'Audit generation and audit records can be generated from various components within the application server. The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records (e.g., auditable events, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked).

The events occurring must be time-correlated in order to conduct accurate forensic analysis. In addition, the correlation must meet a certain tolerance criteria. For instance, DoD may define that the time stamps of different audited events must not differ by any amount greater than ten seconds. It is also acceptable for the application server to utilize an external auditing tool that provides this capability.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'JDBC Data Sources' 
3. From the list of data sources, select the one named 'opss-audit-DBDS', which connects to the IAU_APPEND schema of the audit database. Note the value in the 'JNDI name' field.
4. To verify, select 'Configuration' tab -> 'Connection Pool' tab 
5. Ensure the 'URL' and 'Properties' fields contain the correct connection values for the IAU_APPEND schema
6. To test, select 'Monitoring' tab, select a server from the list and click 'Test Data Source'. Ensure test was successful. Repeat for each server in the list 
7. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Security Provider Configuration' 
8. Beneath 'Audit Service' section, click 'Configure' button 
9. Ensure 'Data Source JNDI Name' value matches the JNDI Name value from data source in step 3 above
10. Repeat steps 2-6 for data source named 'wls-wldf-storeDS' and WLS schema
11. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
12. Within the 'Search' panel, expand 'Selected Targets'
13. Use the list of targets to navigate and drill into the log files across the domain

If any of the targets are not being logged, this is a finding."
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
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39159r628596_chk'
  tag severity: 'low'
  tag gid: 'V-235940'
  tag rid: 'SV-235940r628598_rule'
  tag stig_id: 'WBLC-02-000065'
  tag gtitle: 'SRG-APP-000086-AS-000048'
  tag fix_id: 'F-39122r628597_fix'
  tag 'documentable'
  tag legacy: ['SV-70483', 'V-56229']
  tag cci: ['CCI-000174']
  tag nist: ['AU-12 (1)']
end
