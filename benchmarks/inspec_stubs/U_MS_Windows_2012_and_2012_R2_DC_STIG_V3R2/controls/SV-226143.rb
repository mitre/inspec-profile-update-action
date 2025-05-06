control 'SV-226143' do
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
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27845r475752_chk'
  tag severity: 'medium'
  tag gid: 'V-226143'
  tag rid: 'SV-226143r569184_rule'
  tag stig_id: 'WN12-CC-000009'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27833r475753_fix'
  tag 'documentable'
  tag legacy: ['SV-52968', 'V-26577']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
