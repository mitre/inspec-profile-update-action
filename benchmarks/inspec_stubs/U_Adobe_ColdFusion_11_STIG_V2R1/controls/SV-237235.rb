control 'SV-237235' do
  title 'ColdFusion must be set to automatically check for updates.'
  desc 'Security flaws with software applications are discovered daily.  Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities.  To configure the software to discover that a new patch is available is important since administrators may be responsible for multiple servers running different applications and services, making it difficult for the administrator to constantly check for updates.  Enabling the automatic check informs the administrator, allows him to investigate the patch and what is needed to apply the patch and schedule any outages that might be needed, thereby permitting the patch to be installed quickly and efficiently.

Having "Automatically Check for Updates" checked causes ColdFusion to look for updates on every logon.'
  desc 'check', 'Determine if the ColdFusion server has access to either the Adobe patch repository or an internally maintained patch repository.  This may be determined by interviewing the administrator or by reviewing ColdFusion baseline documentation.

If the ColdFusion server has access to a patch repository, the server must check for updates.  To verify that the server is checking for updates, within the Administrator Console, navigate to the "Updates" page under the "Server Updates" menu.  Select the "Settings" tab and verify that the "Automatically Check for Updates" is checked.

If the ColdFusion server has access to either the Adobe patch repository or an internally maintained patch repository and "Automatically Check for Updates" is not checked, this is a finding.

If the ColdFusion server does not have access to Adobe or an internally maintained patch repository, then a manual process must be documented to check for updates.  The documented process must include the location and how often to check for updates.

If the process is not documented or the documented process does not include location and frequency, this is a finding.'
  desc 'fix', 'If the ColdFusion server has access to a patch repository, navigate to the "Updates" page under the "Server Updates" menu.  Select the "Settings" tab and check the "Automatically Check for Updates" setting and select the "Submit Changes" button.

If the ColdFusion server does not have access to a patch repository, document the process to check for updates.  The documented process must include location and how often.'
  impact 0.3
  ref 'DPMS Target Adobe ColdFusion 11'
  tag check_id: 'C-40454r641798_chk'
  tag severity: 'low'
  tag gid: 'V-237235'
  tag rid: 'SV-237235r641800_rule'
  tag stig_id: 'CF11-06-000226'
  tag gtitle: 'SRG-APP-000456-AS-000266'
  tag fix_id: 'F-40417r641799_fix'
  tag 'documentable'
  tag legacy: ['SV-77033', 'V-62543']
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
