control 'SV-235942' do
  title 'Oracle WebLogic must produce process events and severity levels to establish what type of HTTPD-related events and severity levels occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content that may be necessary to satisfy the requirement of this control includes time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked.

Application servers must log all relevant log data that pertains to application server functionality. Examples of relevant data include, but are not limited to Java Virtual Machine (JVM) activity, HTTPD/Web server activity and application server-related system process activity.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for 'AdminServer' target
5. From the list of log files, select 'access.log' and click 'View Log File' button
6. All HTTPD logging of the AdminServer will be displayed
7. Repeat for each managed server

If any managed server or the AdminServer does not have HTTPD events within the access.log file, this is a finding."
  desc 'fix', "1. Access AC
2. From 'Domain Structure', select 'Environment' -> 'Servers' 
3. From the list of servers, select one which needs HTTPD logging enabled
4. Utilize 'Change Center' to create a new change session
5. From 'Logging' tab -> 'HTTP' tab, select 'HTTP access log file enabled' checkbox
6. Click 'Save', and from 'Change Center' click 'Activate Changes' to enable configuration changes"
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39161r628602_chk'
  tag severity: 'low'
  tag gid: 'V-235942'
  tag rid: 'SV-235942r628604_rule'
  tag stig_id: 'WBLC-02-000073'
  tag gtitle: 'SRG-APP-000095-AS-000056'
  tag fix_id: 'F-39124r628603_fix'
  tag 'documentable'
  tag legacy: ['SV-70487', 'V-56233']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
