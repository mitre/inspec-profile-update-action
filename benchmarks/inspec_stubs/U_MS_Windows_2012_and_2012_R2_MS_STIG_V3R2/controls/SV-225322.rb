control 'SV-225322' do
  title 'The ISATAP IPv6 transition technology must be disabled.'
  desc 'IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\

Value Name: ISATAP_State

Type: REG_SZ
Value: Disabled'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> "Set ISATAP State" to "Enabled: Disabled State".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27021r471308_chk'
  tag severity: 'medium'
  tag gid: 'V-225322'
  tag rid: 'SV-225322r569185_rule'
  tag stig_id: 'WN12-CC-000009'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27009r471309_fix'
  tag 'documentable'
  tag legacy: ['V-26577', 'SV-52968']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
