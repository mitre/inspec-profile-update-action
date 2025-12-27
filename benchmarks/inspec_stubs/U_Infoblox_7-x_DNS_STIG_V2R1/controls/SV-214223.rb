control 'SV-214223' do
  title 'Infoblox Grid configuration must be backed up on a regular basis.'
  desc 'The Infoblox Grid Master is the central point of management within an Infoblox Grid. The Grid Master retains a full copy of the configuration used for the entire Grid. In the event of system failure, a configuration backup must be preserved. An Infoblox member may also be configured as a Grid Master Candidate which is a synchronized to the Grid Master. The Candidate can be promoted in the event of system failure on the Grid Master.'
  desc 'check', 'Navigate to Grid >> Grid Manager >> Members tab.

In the toolbar click the drop-down menu for "Backup", "Schedule Backup".
Verify configuration of a remote backup option (TFTP, FTP, or SCP).
Review the existence of backup files on the remote system.

If a remote backup system is not configured, or a local backup procedure is not documented, this is a finding.

If no remote or local backup is configured, but the Grid contains a Grid Master candidate, the severity of the finding is reduced.'
  desc 'fix', 'Navigate to Grid >> Grid Manager >> Members tab.

In the toolbar click the drop-down menu for "Backup", "Schedule Backup".
Configure remote backup to TFTP, FTP, or SCP.
When complete, click "Save & Close" to save the changes and exit the "Properties" screen.

Perform a service restart if necessary. 

Review the existence of backup files on the remote system.'
  impact 0.5
  ref 'DPMS Target Infoblox 7.x DNS'
  tag check_id: 'C-15438r295932_chk'
  tag severity: 'medium'
  tag gid: 'V-214223'
  tag rid: 'SV-214223r612370_rule'
  tag stig_id: 'IDNS-7X-000980'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-15436r295933_fix'
  tag 'documentable'
  tag legacy: ['SV-83115', 'V-68625']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
