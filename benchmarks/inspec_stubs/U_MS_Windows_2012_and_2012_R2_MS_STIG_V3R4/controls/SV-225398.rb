control 'SV-225398' do
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
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27097r471536_chk'
  tag severity: 'medium'
  tag gid: 'V-225398'
  tag rid: 'SV-225398r569185_rule'
  tag stig_id: 'WN12-CC-000125'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-27085r471537_fix'
  tag 'documentable'
  tag legacy: ['V-36714', 'SV-51754']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
