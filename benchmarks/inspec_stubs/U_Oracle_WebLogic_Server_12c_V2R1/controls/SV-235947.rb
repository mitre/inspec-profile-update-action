control 'SV-235947' do
  title 'Oracle WebLogic must produce audit records containing sufficient information to establish the sources of the events.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application specific events, success/fail indications, filenames involved, access control or flow control rules invoked. 

Without information establishing the source of activity, the value of audit records from a forensics perspective is questionable. 

Examples of activity sources include, but are not limited to, application process sources such as one process affecting another process, user-related activity, and activity resulting from remote network system access (IP addresses).'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for any of the managed server or 'Application Deployment' type targets (not AdminServer)
5. From the list of log files, select '<server-name>.log', 'access.log' or '<server-name>-diagnostic.log' and click 'View Log File' button
6. Select any record which appears in the log message table
7. Source of audit event will be displayed in 'Host', 'Host IP Address', 'Thread ID', 'REMOTE_HOST' fields of the message detail (beneath the table), depending on which logfile and target type is selected
8. Repeat for each target

If any of the targets generate audit records without sufficient information to establish the source of the events, this is a finding."
  desc 'fix', "1. If managed server or deployments do not appear in the list of log files, the 'JRF Template' must be applied to the server/cluster
2. Access EM 
3. Select the server or cluster from the navigation tree
4. If the 'Apply JRF Template' button appears, click this button and wait for the confirmation message that the template has been successfully applied
5. Again, select the server or cluster from the navigation tree
6. Click the 'Shut Down...' button, and click 'Shutdown' in the confirmation popup. Wait for server or cluster to shut down.
7. Click the 'Start Up' button for the server or cluster to start up again"
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39166r628617_chk'
  tag severity: 'low'
  tag gid: 'V-235947'
  tag rid: 'SV-235947r628619_rule'
  tag stig_id: 'WBLC-02-000078'
  tag gtitle: 'SRG-APP-000098-AS-000061'
  tag fix_id: 'F-39129r628618_fix'
  tag 'documentable'
  tag legacy: ['SV-70497', 'V-56243']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
