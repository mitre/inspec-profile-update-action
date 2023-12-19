control 'SV-235941' do
  title 'Oracle WebLogic must generate audit records for the DoD-selected list of auditable events.'
  desc 'Audit records can be generated from various components within the application server. The list of audited events is the set of events for which audits are to be generated. 

This set of events is typically a subset of the list of all events for which the system is capable of generating audit records (e.g., auditable events, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked).

The DoD-required auditable events are events that assist in intrusion detection and forensic analysis. Failure to capture them increases the likelihood that an adversary can breach the system without detection.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for 'AdminServer' target
5. From the list of log files, select 'access.log' and click 'View Log File' button
6. All HTTPD, JVM, AS process event and other logging of the AdminServer will be displayed
7. Repeat for each managed server

If there are no events being logged for any of the managed servers or the AdminServer, this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs logging enabled
4. Utilize 'Change Center' to create a new change session
5. From 'Logging' tab -> 'HTTP' tab, select 'HTTP access log file enabled' checkbox. Click 'Save'
6. From 'Logging' tab -> 'General' tab, set the 'Log file name' field to 'logs/<server-name>.log. Click 'Save'
7. From 'Change Center' click 'Activate Changes' to enable configuration changes
8. Access EM 
9. Expand the domain from the navigation tree, and select the server which needs JVM logging configured
10. Use the dropdown to select 'WebLogic Server' -> 'Logs' -> 'Log Configuration'
11. Select the 'Log Levels' tab, and within the table, expand 'Root Logger' node
12. Set 'Oracle Diagnostic Logging Level' value to 'WARNING' and click 'Apply'"
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39160r628599_chk'
  tag severity: 'low'
  tag gid: 'V-235941'
  tag rid: 'SV-235941r628601_rule'
  tag stig_id: 'WBLC-02-000069'
  tag gtitle: 'SRG-APP-000091-AS-000052'
  tag fix_id: 'F-39123r628600_fix'
  tag 'documentable'
  tag legacy: ['SV-70485', 'V-56231']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
