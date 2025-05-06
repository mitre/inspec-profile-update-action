control 'SV-235939' do
  title 'Oracle WebLogic must protect against an individual falsely denying having performed a particular action.'
  desc 'Non-repudiation of actions taken is required in order to maintain application integrity. Examples of particular actions taken by individuals include creating information, sending a message, approving information (e.g., indicating concurrence or signing a contract), and receiving a message. 

Non-repudiation protects individuals against later claims by an author of not having authored a particular document, a sender of not having transmitted a message, a receiver of not having received a message, or a signatory of not having signed a document. 

Typical application server actions requiring non-repudiation will be related to application deployment among developer/users and administrative actions taken by admin personnel.'
  desc 'check', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Audit Policy' 
3. Select 'Oracle Platform Security Services' from the 'Audit Component Name' dropdown
4. Beneath 'Audit Policy Settings' section, ensure that the value 'Custom' is set in the 'Audit Level' dropdown
5. Beneath 'Audit Policy Settings' section, ensure that every checkbox is selected under the 'Select For Audit' column of the policy category table
6. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Logs' -> 'View Log Messages'
7. Within the 'Search' panel, expand 'Selected Targets'
8. Click 'Target Log Files' icon for any of the managed server or 'Application Deployment' type targets (not AdminServer)
9. From the list of log files, select '<server-name>.log', 'access.log' or '<server-name>-diagnostic.log' and click 'View Log File' button
10. User or process associated with audit event will be displayed in 'User' column
11. If 'User' column does not appear, use 'View' button -> 'Columns' list to add 'User' field, or select individual message in log message table and view the message detail (beneath the table)
12. Repeat steps 6-11 for each target

If the user is not part of the audit events, this is a finding."
  desc 'fix', "1. Access EM 
2. Select the domain from the navigation tree, and use the dropdown to select 'WebLogic Domain' -> 'Security' -> 'Audit Policy' 
3. Select 'Oracle Platform Security Services' from the 'Audit Component Name' dropdown
4. Beneath 'Audit Policy Settings' section, select 'Custom' from the 'Audit Level' dropdown
5. Once it is enabled, click the 'Audit All Events' button and ensure every checkbox is selected under the 'Select For Audit' column of the policy category table. Click 'Apply'
6. If managed server or deployments do not appear in the list of log files, the 'JRF Template' must be applied to the server/cluster
7. Access EM 
8. Select the server or cluster from the navigation tree
9. If the 'Apply JRF Template' button appears, click this button and wait for the confirmation message that the template has been successfully applied
10. Again, select the server or cluster from the navigation tree
11. Click the 'Shut Down...' button, and click 'Shutdown' in the confirmation popup. Wait for server or cluster to shut down
12. Click the 'Start Up' button for the server or cluster to start up again"
  impact 0.5
  ref 'DPMS Target Oracle WebLogic Server 12c'
  tag check_id: 'C-39158r628593_chk'
  tag severity: 'medium'
  tag gid: 'V-235939'
  tag rid: 'SV-235939r628595_rule'
  tag stig_id: 'WBLC-02-000062'
  tag gtitle: 'SRG-APP-000080-AS-000045'
  tag fix_id: 'F-39121r628594_fix'
  tag 'documentable'
  tag legacy: ['SV-70481', 'V-56227']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
