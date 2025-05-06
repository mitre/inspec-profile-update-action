control 'SV-253416' do
  title 'The Windows Remote Management (WinRM) client must not use Basic authentication.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowBasic

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Allow Basic authentication" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56869r829330_chk'
  tag severity: 'high'
  tag gid: 'V-253416'
  tag rid: 'SV-253416r829332_rule'
  tag stig_id: 'WN11-CC-000330'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-56819r829331_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
