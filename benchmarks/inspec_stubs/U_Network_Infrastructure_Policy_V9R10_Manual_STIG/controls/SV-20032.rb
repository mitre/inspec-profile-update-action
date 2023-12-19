control 'SV-20032' do
  title 'Intrusion Detection and Prevention System (IDPS) traffic between the sensor and the security management or sensor data collection servers must traverse a dedicated Virtual Local Area Network (VLAN) logically separating IDPS traffic from all other enclave traffic.'
  desc 'All IDPS data collected by agents in the enclave at required locations must also be protected by logical separation when in transit from the agent to the management or database servers located on the Network Management subnet.'
  desc 'check', 'Review the network topology diagram and interview the ISSO to determine how the IDPS traffic between the sensor and the security management or sensor data collection servers is transported.

If the IDPS traffic does not traverse a dedicated VLAN logically separating IDPS traffic from all other enclave traffic, this is a finding.'
  desc 'fix', 'Design a communications path for OOB traffic or create a VLAN for IDPS traffic to protect the data.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-21132r2_chk'
  tag severity: 'medium'
  tag gid: 'V-18497'
  tag rid: 'SV-20032r2_rule'
  tag stig_id: 'NET-IDPS-025'
  tag gtitle: 'IDPS data from agent to MGT network is not secured'
  tag fix_id: 'F-19087r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
