control 'SV-226218' do
  title 'The Windows Remote Management (WinRM) client must not use Digest authentication.'
  desc 'Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowDigest

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client -> "Disallow Digest authentication" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27920r475977_chk'
  tag severity: 'medium'
  tag gid: 'V-226218'
  tag rid: 'SV-226218r794450_rule'
  tag stig_id: 'WN12-CC-000125'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-27908r475978_fix'
  tag 'documentable'
  tag legacy: ['SV-51754', 'V-36714']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
