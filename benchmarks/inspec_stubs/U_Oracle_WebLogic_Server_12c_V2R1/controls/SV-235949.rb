control 'SV-235949' do
  title 'Oracle WebLogic must produce audit records containing sufficient information to establish the identity of any user/subject or process associated with the event.'
  desc 'Information system auditing capability is critical for accurate forensic analysis. Audit record content that may be necessary to satisfy the requirement of this control, includes: time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked. 

Application servers have differing levels of logging capabilities which can be specified by setting a verbosity level. The application server must, at a minimum, be capable of establishing the identity of any user or process that is associated with any particular event.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
3. Within the 'Search' panel, expand 'Selected Targets'
4. Click 'Target Log Files' icon for any of the managed server or 'Application Deployment' type targets (not AdminServer)
5. From the list of log files, select '<server-name>.log', 'access.log' or '<server-name>-diagnostic.log' and click 'View Log File' button
6. User or process associated with audit event will be displayed in 'User' column
7. If 'User' column does not appear, use 'View' button -> 'Columns' list to add 'User' field, or select individual message in log message table and view the message detail (beneath the table)
8. Repeat for each target

If any of the targets generate audit records without sufficient information to establish the identity of any user/subject or process, this is a finding."
  desc 'fix', "1. If managed server or deployments do not appear in the list of log files, the 'JRF Template' must be applied to the server/cluster
2. Access EM 
3. Select the server or cluster from the navigation tree
4. If the 'Apply JRF Template' button appears, click this button and wait for the confirmation message that the template has been successfully applied
5. Again, select the server or cluster from the navigation tree
6. Click the 'Shut Down...' button, and click 'Shutdown' in the confirmation popup. Wait for server or cluster to shut down
7. Click the 'Start Up' button for the server or cluster to start up again"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39168r628623_chk'
  tag severity: 'medium'
  tag gid: 'V-235949'
  tag rid: 'SV-235949r628625_rule'
  tag stig_id: 'WBLC-02-000080'
  tag gtitle: 'SRG-APP-000100-AS-000063'
  tag fix_id: 'F-39131r628624_fix'
  tag 'documentable'
  tag legacy: ['SV-70501', 'V-56247']
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
