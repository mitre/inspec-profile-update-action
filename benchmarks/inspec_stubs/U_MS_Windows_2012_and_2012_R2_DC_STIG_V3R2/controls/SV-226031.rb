control 'SV-226031' do
  title 'Users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.'
  desc 'Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadvertently introduced during a session that has been granted full privileges.'
  desc 'check', 'Verify each user with administrative privileges has been assigned a unique administrative account separate from their standard user account. 

If users with administrative privileges do not have separate accounts for administrative functions and standard user functions, this is a finding.'
  desc 'fix', 'Ensure each user with administrative privileges has a separate account for user duties and one for privileged duties.'
  impact 0.7
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27733r475416_chk'
  tag severity: 'high'
  tag gid: 'V-226031'
  tag rid: 'SV-226031r569184_rule'
  tag stig_id: 'WN12-00-000005'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27721r475417_fix'
  tag 'documentable'
  tag legacy: ['SV-51576', 'V-36659']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
