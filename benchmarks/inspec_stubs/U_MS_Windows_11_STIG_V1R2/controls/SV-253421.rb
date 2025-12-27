control 'SV-253421' do
  title 'The Windows Remote Management (WinRM) client must not use Digest authentication.'
  desc 'Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowDigest

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Disallow Digest authentication" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56874r829345_chk'
  tag severity: 'medium'
  tag gid: 'V-253421'
  tag rid: 'SV-253421r829347_rule'
  tag stig_id: 'WN11-CC-000360'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-56824r829346_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
