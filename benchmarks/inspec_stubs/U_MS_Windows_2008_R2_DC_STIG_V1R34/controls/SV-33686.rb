control 'SV-33686' do
  title 'The IP-HTTPS IPv6 transition technology will be disabled.'
  desc 'IPv6 transition technologies which tunnel packets through other protocols do not provide visibility.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\IPHTTPS\\IPHTTPSInterface\\

Value Name: IPHTTPS_ClientState

Type: REG_DWORD
Value: 3'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> “IP-HTTPS State” to “Enabled: Disabled State”.  

Note: "IPHTTPS URL:" must be entered in policy even if set to Disabled State, enter “about:blank”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-34137r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26576'
  tag rid: 'SV-33686r1_rule'
  tag stig_id: 'WINNE-000002'
  tag gtitle: 'IP-HTTPS State'
  tag fix_id: 'F-29827r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
