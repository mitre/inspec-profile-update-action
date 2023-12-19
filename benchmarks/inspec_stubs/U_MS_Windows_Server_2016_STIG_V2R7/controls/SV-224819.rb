control 'SV-224819' do
  title 'Users with Administrative privileges must have separate accounts for administrative duties and normal operational tasks.'
  desc 'Using a privileged account to perform routine functions makes the computer vulnerable to malicious software inadvertently introduced during a session that has been granted full privileges.'
  desc 'check', 'Verify each user with administrative privileges has been assigned a unique administrative account separate from their standard user account. 

If users with administrative privileges do not have separate accounts for administrative functions and standard user functions, this is a finding.'
  desc 'fix', 'Ensure each user with administrative privileges has a separate account for user duties and one for privileged duties.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26510r465359_chk'
  tag severity: 'high'
  tag gid: 'V-224819'
  tag rid: 'SV-224819r569186_rule'
  tag stig_id: 'WN16-00-000010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26498r465360_fix'
  tag 'documentable'
  tag legacy: ['SV-87869', 'V-73217']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
