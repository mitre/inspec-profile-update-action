control 'SV-225241' do
  title 'Users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.'
  desc 'Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadvertently introduced during a session that has been granted full privileges.'
  desc 'check', 'Verify each user with administrative privileges has been assigned a unique administrative account separate from their standard user account. 

If users with administrative privileges do not have separate accounts for administrative functions and standard user functions, this is a finding.'
  desc 'fix', 'Ensure each user with administrative privileges has a separate account for user duties and one for privileged duties.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-26940r471065_chk'
  tag severity: 'high'
  tag gid: 'V-225241'
  tag rid: 'SV-225241r569185_rule'
  tag stig_id: 'WN12-00-000005'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26928r471066_fix'
  tag 'documentable'
  tag legacy: ['SV-51576', 'V-36659']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
