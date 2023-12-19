control 'SV-206813' do
  title 'The Voice Video Session Manager must control flow within the enclave based on approved dial plans.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data. 

For voice and video session managers, session flow of information is controlled by dial plans that coordinate connections between endpoints. Dial plans can also reduce connection costs in some cases, relying on routes across the DoDIN rather than over commercial services. Session managers can routes connections to known commercial services and DoD providers. Using DoDIN network paths reduces the risk of an adversary to intercept calls. However, dial plans can be mimicked and therefore are only part of a defense in depth approach.'
  desc 'check', 'Verify the Voice Video Session Manager controls flow within the enclave based on approved dial plans.

If the Voice Video Session Manager does not control flow within the enclave based on approved dial plans, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to control flow within the enclave based on approved dial plans.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7068r364628_chk'
  tag severity: 'medium'
  tag gid: 'V-206813'
  tag rid: 'SV-206813r508661_rule'
  tag stig_id: 'SRG-NET-000018-VVSM-00026'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-7068r364629_fix'
  tag 'documentable'
  tag legacy: ['SV-76545', 'V-62055']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
