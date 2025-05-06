control 'SV-235948' do
  title 'Oracle WebLogic must produce audit records that contain sufficient information to establish the outcome (success or failure) of application server and application events.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application specific events, success/fail indications, filenames involved, access control or flow control rules invoked.

Success and failure indicators ascertain the outcome of a particular application server event of function. As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for any of the managed server or 'Application Deployment' type targets (not AdminServer)
5. From the list of log files, select '<server-name>.log', 'access.log' or '<server-name>-diagnostic.log' and click 'View Log File' button
6. Outcome of audit event will be displayed in 'Message Type' column. 'Error' or 'Exception' indicates failures, others message types indicate success
7. If 'Message Type' column does not appear, use 'View' button -> 'Columns' list to add 'Message Type' field, or select individual message in log message table and view the message detail (beneath the table)
8. Repeat for each target

If any of the targets generate audit records without sufficient information to establish the outcome of the event, this is a finding."
  desc 'fix', "1. If managed server or deployments do not appear in the list of log files, the 'JRF Template' must be applied to the server/cluster
2. Access EM 
3. Select the server or cluster from the navigation tree
4. If the 'Apply JRF Template' button appears, click this button and wait for the confirmation message that the template has been successfully applied
5. Again, select the server or cluster from the navigation tree
6. Click the 'Shut Down...' button, and click 'Shutdown' in the confirmation popup. Wait for server or cluster to shut down.
7. Click the 'Start Up' button for the server or cluster to start up again"
  impact 0.3
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39167r628620_chk'
  tag severity: 'low'
  tag gid: 'V-235948'
  tag rid: 'SV-235948r628622_rule'
  tag stig_id: 'WBLC-02-000079'
  tag gtitle: 'SRG-APP-000099-AS-000062'
  tag fix_id: 'F-39130r628621_fix'
  tag 'documentable'
  tag legacy: ['SV-70499', 'V-56245']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
