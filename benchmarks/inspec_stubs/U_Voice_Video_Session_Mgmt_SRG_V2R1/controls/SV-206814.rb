control 'SV-206814' do
  title 'The Voice Video Session Manager must control flow outside the enclave based on approved dial plans.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data. 

For voice and video session managers, session flow of information is controlled by dial plans that coordinate connections between endpoints. Dial plans can also reduce connection costs in some cases, relying on routes across the DoDIN rather than over commercial services. Session managers can routes connections to known commercial services and DoD providers. Using DoDIN network paths reduces the risk of an adversary to intercept calls. However, dial plans can be mimicked and therefore are only part of a defense in depth approach.'
  desc 'check', 'Verify the Voice Video Session Manager controls flow outside the enclave based on approved dial plans.

If the Voice Video Session Manager does not control flow outside the enclaves based on approved dial plans, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to control flow outside the enclave based on approved dial plans.'
  impact 0.7
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7069r364631_chk'
  tag severity: 'high'
  tag gid: 'V-206814'
  tag rid: 'SV-206814r508661_rule'
  tag stig_id: 'SRG-NET-000019-VVSM-00027'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7069r364632_fix'
  tag 'documentable'
  tag legacy: ['SV-76547', 'V-62057']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
