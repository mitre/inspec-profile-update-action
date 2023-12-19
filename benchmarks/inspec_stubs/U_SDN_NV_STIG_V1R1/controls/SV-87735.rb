control 'SV-87735' do
  title 'Southbound API management plane traffic for provisioning and configuring virtual network elements within the SDN infrastructure must be authenticated using a FIPS-approved message authentication code algorithm.'
  desc 'Management and orchestration systems within the SDN framework instantiate, deploy, and configure virtual network elements. These systems also define the virtual network topology by specifying the connectivity between the network elements and the workloads, both virtual and physical.

If a hypervisor host within the SDN infrastructure were to receive fictitious information from a rogue management or orchestration system as a result of no authentication, the virtual network topology could be altered by deploying rogue network elements to create non-optimized network paths, resulting in inefficient application and business processes. By altering the network topology, the attacker would have the ability force traffic to bypass security controls.'
  desc 'check', 'Verify that all southbound API management plane traffic is authenticated using a FIPS-approved message authentication code algorithm.

Review SDN management and orchestration systems, as well as all hypervisor hosts that compose the NVP framework, to determine if a FIPS-approved message authentication code algorithm is used to ensure the authenticity and integrity of messages used to deploy and configure software-defined network elements. 

If southbound API management plane traffic is not authenticated using a FIPS-approved message authentication code algorithm, this is a finding.'
  desc 'fix', 'Configure these components to use  a FIPS-approved message authentication code algorithm to authenticate southbound API management messages.'
  impact 0.5
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73217r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73083'
  tag rid: 'SV-87735r1_rule'
  tag stig_id: 'NET-SDN-006'
  tag gtitle: 'NET-SDN-006'
  tag fix_id: 'F-79529r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
