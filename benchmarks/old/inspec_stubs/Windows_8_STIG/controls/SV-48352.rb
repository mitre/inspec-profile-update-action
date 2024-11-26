control 'SV-48352' do
  title 'The Windows Remote Management (WinRM) client must not use Digest authentication.'
  desc 'Digest authentication is not as strong as other options and may be subject to man-in-the-middle attacks.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowDigest

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client -> "Disallow Digest authentication" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45024r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36714'
  tag rid: 'SV-48352r2_rule'
  tag stig_id: 'WN08-CC-000125'
  tag gtitle: 'WINCC-000125'
  tag fix_id: 'F-41484r1_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
