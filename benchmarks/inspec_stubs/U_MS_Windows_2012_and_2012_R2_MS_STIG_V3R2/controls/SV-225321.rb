control 'SV-225321' do
  title 'The IP-HTTPS IPv6 transition technology must be disabled.'
  desc 'IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\IPHTTPS\\IPHTTPSInterface\\

Value Name: IPHTTPS_ClientState

Type: REG_DWORD
Value: 3'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> "Set IP-HTTPS State" to "Enabled: Disabled State".  

Note: "IPHTTPS URL:" must be entered in the policy even if set to Disabled State.  Enter "about:blank".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27020r471305_chk'
  tag severity: 'medium'
  tag gid: 'V-225321'
  tag rid: 'SV-225321r569185_rule'
  tag stig_id: 'WN12-CC-000008'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27008r471306_fix'
  tag 'documentable'
  tag legacy: ['V-26576', 'SV-52969']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
