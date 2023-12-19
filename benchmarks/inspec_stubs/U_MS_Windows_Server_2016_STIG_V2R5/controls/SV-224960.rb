control 'SV-224960' do
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
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26651r465782_chk'
  tag severity: 'medium'
  tag gid: 'V-224960'
  tag rid: 'SV-224960r569186_rule'
  tag stig_id: 'WN16-CC-000520'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-26639r465783_fix'
  tag 'documentable'
  tag legacy: ['SV-88261', 'V-73597']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
