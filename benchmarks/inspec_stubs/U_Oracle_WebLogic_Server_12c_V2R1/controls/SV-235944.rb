control 'SV-235944' do
  title 'Oracle WebLogic must produce process events and security levels to establish what type of Oracle WebLogic process events and severity levels occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content that may be necessary to satisfy the requirement of this control, includes: time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Application servers must log all relevant log data that pertains to application server functionality. Examples of relevant data include, but are not limited to, Java Virtual Machine (JVM) activity, HTTPD activity and application server-related system process activity.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for 'AdminServer' target
5. From the list of log files, select '<server-name>.log' and click 'View Log File' button
6. All AS process logging of the AdminServer will be displayed
7. Repeat for each managed server

If the managed servers or AdminServer does not have process events, this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs AS process logging configured
4. Utilize 'Change Center' to create a new change session
5. From 'Logging' tab -> 'General' tab, set the 'Log file name' field to 'logs/<server-name>.log
6. Click 'Save', and from 'Change Center' click 'Activate Changes' to enable configuration changes"
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39163r628608_chk'
  tag severity: 'low'
  tag gid: 'V-235944'
  tag rid: 'SV-235944r628610_rule'
  tag stig_id: 'WBLC-02-000075'
  tag gtitle: 'SRG-APP-000095-AS-000056'
  tag fix_id: 'F-39126r628609_fix'
  tag 'documentable'
  tag legacy: ['SV-70491', 'V-56237']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
