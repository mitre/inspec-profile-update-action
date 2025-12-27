control 'SV-48349' do
  title 'The Teredo IPv6 transition technology must be disabled.'
  desc 'IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\

Value Name: Teredo_State

Type: REG_SZ
Value: Disabled'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> "Set Teredo State" to "Enabled: Disabled State".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45019r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26578'
  tag rid: 'SV-48349r3_rule'
  tag stig_id: 'WN08-CC-000010'
  tag gtitle: 'Teredo State'
  tag fix_id: 'F-41480r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
