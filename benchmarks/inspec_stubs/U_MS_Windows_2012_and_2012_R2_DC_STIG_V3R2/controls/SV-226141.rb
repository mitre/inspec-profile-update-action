control 'SV-226141' do
  title 'The 6to4 IPv6 transition technology must be disabled.'
  desc 'IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\

Value Name: 6to4_State

Type: REG_SZ
Value: Disabled'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> "Set 6to4 State" to "Enabled: Disabled State".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27843r475746_chk'
  tag severity: 'medium'
  tag gid: 'V-226141'
  tag rid: 'SV-226141r569184_rule'
  tag stig_id: 'WN12-CC-000007'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27831r475747_fix'
  tag 'documentable'
  tag legacy: ['SV-52970', 'V-26575']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
