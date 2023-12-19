control 'SV-48355' do
  title 'The IP-HTTPS IPv6 transition technology must be disabled.'
  desc 'IPv6 transition technologies, which tunnel packets through other protocols, do not provide visibility.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\TCPIP\\v6Transition\\IPHTTPS\\IPHTTPSInterface\\

Value Name: IPHTTPS_ClientState

Type: REG_DWORD
Value: 3'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> TCPIP Settings -> IPv6 Transition Technologies -> "Set IP-HTTPS State" to "Enabled: Disabled State".  

Note: "IPHTTPS URL:" must be entered in the policy even if set to Disabled State.  Enter "about:blank".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45027r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26576'
  tag rid: 'SV-48355r3_rule'
  tag stig_id: 'WN08-CC-000008'
  tag gtitle: 'IP-HTTPS State'
  tag fix_id: 'F-41487r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
