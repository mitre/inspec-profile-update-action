control 'SV-31589' do
  title 'Connection to the Internet for IBM remote support must be in compliance with mitigations specified in the Ports and Protocols and Services Management (PPSM) requirements.'
  desc 'Failure to securely connect to remote sites can leave systems open to multiple attacks and security violations through the network. Failure to securely implement remote support connections can lead to unauthorized access or denial of service attacks on theHardware Management Console.'
  desc 'check', 'Have the Network Security Engineer check, that the remote Internet connection for IBM RSF support has met the mitigations outlined in Vulnerability Analysis for port 443/SSL in the PPSM requirements.'
  desc 'fix', 'Have the Network Security Officer validate that the Internet connection meets the specifications in the PPSM requirements.'
  impact 0.7
  ref 'DPMS Target IBM HMC Application'
  tag check_id: 'C-31953r1_chk'
  tag severity: 'high'
  tag gid: 'V-25405'
  tag rid: 'SV-31589r2_rule'
  tag stig_id: 'HMC0225'
  tag gtitle: 'HMC0225'
  tag fix_id: 'F-28361r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Network Security Officer']
  tag ia_controls: 'EBRP-1, EBRU-1'
  tag cci: ['CCI-002310']
  tag nist: ['AC-17 a']
end
