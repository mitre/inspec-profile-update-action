control 'SV-233884' do
  title 'Infoblox Grid configuration must be backed up on a regular basis.'
  desc 'The Infoblox Grid Master is the central point of management within an Infoblox Grid. The Grid Master retains a full copy of the configuration used for the entire Grid. In the event of system failure, a configuration backup must be preserved. 

An Infoblox Grid member may also be configured as a Grid Master Candidate, which is synchronized to the Grid Master. The Grid Master Candidate can be promoted in the event of system failure on the Grid Master.'
  desc 'check', '1. Navigate to Grid >> Grid Manager >> Members tab. 
2. In the toolbar, click the drop-down menu for "Backup", "Schedule Backup".  
3. Verify configuration of a remote backup option (TFTP, FTP, or SCP). Review the existence of backup files on the remote system.  

If a remote backup system is not configured, or a local backup procedure is not documented, this is a finding.

If no remote or local backup is configured, but the Grid contains a Grid Master candidate, the severity of the finding is reduced.'
  desc 'fix', '1. Navigate to Grid >> Grid Manager >> Members tab.  
2. In the toolbar, click the drop-down menu for "Backup", "Schedule Backup". Configure remote backup to TFTP, FTP, or SCP.  
3. When complete, click "Save & Close" to save the changes and exit the "Properties" screen. 
4. Perform a service restart if necessary. 
5. Review the existence of backup files on the remote system.'
  impact 0.5
  ref 'DPMS Target Infoblox 8.x DNS'
  tag check_id: 'C-37069r611172_chk'
  tag severity: 'medium'
  tag gid: 'V-233884'
  tag rid: 'SV-233884r621666_rule'
  tag stig_id: 'IDNS-8X-400026'
  tag gtitle: 'SRG-APP-000516-DNS-000500'
  tag fix_id: 'F-37034r611173_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
