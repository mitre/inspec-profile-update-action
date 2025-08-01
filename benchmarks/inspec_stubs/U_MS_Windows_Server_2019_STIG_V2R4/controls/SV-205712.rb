control 'SV-205712' do
  title 'Windows Server 2019 Windows Remote Management (WinRM) client must not use Digest authentication.'
  desc 'Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks. Disallowing Digest authentication will reduce this potential.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowDigest

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Disallow Digest authentication" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5977r355054_chk'
  tag severity: 'medium'
  tag gid: 'V-205712'
  tag rid: 'SV-205712r569188_rule'
  tag stig_id: 'WN19-CC-000490'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-5977r355055_fix'
  tag 'documentable'
  tag legacy: ['SV-103591', 'V-93505']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
