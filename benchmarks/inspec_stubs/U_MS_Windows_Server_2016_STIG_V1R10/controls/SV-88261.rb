control 'SV-88261' do
  title 'The Windows Remote Management (WinRM) client must not use Digest authentication.'
  desc 'Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks. Disallowing Digest authentication will reduce this potential.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowDigest

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Disallow Digest authentication" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 2016'
  tag check_id: 'C-73679r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73597'
  tag rid: 'SV-88261r1_rule'
  tag stig_id: 'WN16-CC-000520'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-80047r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
