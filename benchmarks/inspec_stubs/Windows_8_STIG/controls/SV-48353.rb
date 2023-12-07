control 'SV-48353' do
  title 'The ISATAP IPv6 transition technology must be disabled.'
  desc 'IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\

Value Name: ISATAP_State

Type: REG_SZ
Value: Disabled'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> "Set ISATAP State" to "Enabled: Disabled State".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45025r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26577'
  tag rid: 'SV-48353r3_rule'
  tag stig_id: 'WN08-CC-000009'
  tag gtitle: 'ISATAP State'
  tag fix_id: 'F-41485r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
