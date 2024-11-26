control 'SV-40097' do
  title 'Media Player must be configured to prevent automatic checking for updates.'
  desc 'Uncontrolled system updates can introduce issues to a system. The automatic check for updates performed by Windows Media Player must be disabled to ensure a constant platform and to prevent the introduction of unknown\\untested software on the system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\WindowsMediaPlayer\\

Value Name: DisableAutoupdate

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Media Player -> "Prevent Automatic Updates" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-46904r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3480'
  tag rid: 'SV-40097r2_rule'
  tag gtitle: 'Media Player - Disable Automatic Updates'
  tag fix_id: 'F-45025r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
