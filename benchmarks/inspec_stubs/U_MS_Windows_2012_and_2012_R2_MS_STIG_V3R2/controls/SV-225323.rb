control 'SV-225323' do
  title 'The Teredo IPv6 transition technology must be disabled.'
  desc 'IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\

Value Name: Teredo_State

Type: REG_SZ
Value: Disabled'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> "Set Teredo State" to "Enabled: Disabled State".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27022r471311_chk'
  tag severity: 'medium'
  tag gid: 'V-225323'
  tag rid: 'SV-225323r569185_rule'
  tag stig_id: 'WN12-CC-000010'
  tag gtitle: 'SRG-OS-000096-GPOS-00050'
  tag fix_id: 'F-27010r471312_fix'
  tag 'documentable'
  tag legacy: ['SV-52967', 'V-26578']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
