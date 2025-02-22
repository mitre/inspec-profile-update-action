control 'SV-254238' do
  title 'Windows Server 2022 users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.'
  desc 'Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadvertently introduced during a session that has been granted full privileges.'
  desc 'check', 'Verify each user with administrative privileges has been assigned a unique administrative account separate from their standard user account. 

If users with administrative privileges do not have separate accounts for administrative functions and standard user functions, this is a finding.'
  desc 'fix', 'Ensure each user with administrative privileges has a separate account for user duties and one for privileged duties.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57723r848528_chk'
  tag severity: 'medium'
  tag gid: 'V-254238'
  tag rid: 'SV-254238r848530_rule'
  tag stig_id: 'WN22-00-000010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57674r848529_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
