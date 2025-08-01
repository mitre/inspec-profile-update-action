control 'SV-235946' do
  title 'Oracle WebLogic must produce audit records containing sufficient information to establish where the events occurred.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content that may be necessary to satisfy the requirement of this control includes time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked. 

Without sufficient information establishing where the audit events occurred, investigation into the cause of events is severely hindered. 

In addition to logging relevant data, application servers must also log information to indicate the location of these events. Examples of relevant data include, but are not limited to, Java Virtual Machine (JVM) activity, HTTPD activity and application server-related system process activity.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for any of the managed server or 'Application Deployment' type targets (not AdminServer)
5. From the list of log files, select '<server-name>.log', 'access.log' or '<server-name>-diagnostic.log' and click 'View Log File' button
6. Select any record which appears in the log message table
7. Location of audit event will be displayed in 'Component' and 'Module' fields of the message detail (beneath the table)
8. Repeat for each target

If any of the targets generate audit records without sufficient information to establish where the event occurred, this is a finding."
  desc 'fix', "1. If managed server or deployments do not appear in the list of log files, the 'JRF Template' must be applied to the server/cluster
2. Access EM 
3. Select the server or cluster from the navigation tree
4. If the 'Apply JRF Template' button appears, click this button and wait for the confirmation message that the template has been successfully applied
5. Again, select the server or cluster from the navigation tree
6. Click the 'Shut Down...' button, and click 'Shutdown' in the confirmation popup. Wait for server or cluster to shut down.
7. Click the 'Start Up' button for the server or cluster to start up again"
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39165r628614_chk'
  tag severity: 'low'
  tag gid: 'V-235946'
  tag rid: 'SV-235946r628616_rule'
  tag stig_id: 'WBLC-02-000077'
  tag gtitle: 'SRG-APP-000097-AS-000060'
  tag fix_id: 'F-39128r628615_fix'
  tag 'documentable'
  tag legacy: ['SV-70495', 'V-56241']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
