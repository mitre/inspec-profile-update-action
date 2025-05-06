control 'SV-36007' do
  title 'The ISATAP IPv6 transition technology will be disabled.'
  desc 'IPv6 transition technologies which tunnel packets through other protocols do not provide visibility.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\

Value Name: ISATAP_State

Type: REG_SZ
Value: Disabled'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> “ISATAP State” to “Enabled: Disabled State”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-34138r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26577'
  tag rid: 'SV-36007r1_rule'
  tag stig_id: 'WINNE-000003'
  tag gtitle: 'ISATAP State'
  tag fix_id: 'F-29828r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
