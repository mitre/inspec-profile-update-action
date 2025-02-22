control 'SV-235943' do
  title 'Oracle WebLogic must produce audit records containing sufficient information to establish what type of JVM-related events and severity levels occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content that may be necessary to satisfy the requirement of this control, includes: time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Application servers must log all relevant log data that pertains to application server functionality. Examples of relevant data include, but are not limited to, Java Virtual Machine (JVM) activity, HTTPD activity and application server-related system process activity.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for 'AdminServer' target
5. From the list of log files, select '<server-name>-diagnostic.log' and click 'View Log File' button
6. All JVM logging of the AdminServer will be displayed
7. Repeat for each managed server

If there are no JVM-related events for the managed servers or the AdminServer, this is a finding."
  desc 'fix', "1. Access EM 
2. Expand the domain from the navigation tree, and select the server which needs JVM logging configured
3. Use the dropdown to select 'WebLogic Server' -> 'Logs' -> 'Log Configuration'
4. Select the 'Log Levels' tab, and within the table, expand 'Root Logger' node
5. Set 'Oracle Diagnostic Logging Level' value to 'WARNING' and click 'Apply'"
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39162r628605_chk'
  tag severity: 'low'
  tag gid: 'V-235943'
  tag rid: 'SV-235943r628607_rule'
  tag stig_id: 'WBLC-02-000074'
  tag gtitle: 'SRG-APP-000095-AS-000056'
  tag fix_id: 'F-39125r628606_fix'
  tag 'documentable'
  tag legacy: ['SV-70489', 'V-56235']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
