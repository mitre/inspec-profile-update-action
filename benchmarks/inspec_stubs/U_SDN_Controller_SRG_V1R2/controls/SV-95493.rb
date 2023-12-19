control 'SV-95493' do
  title 'The SDN controller must be configured to authenticate northbound Application Program Interface (API) messages received from business applications and management systems using a FIPS-approved message authentication code algorithm.'
  desc 'The SDN controller determines how traffic should flow through physical and virtual network devices based on application profiles, network infrastructure resources, security policies, and business requirements that it receives via the northbound API. It also receives network service requests from orchestration and management systems to deploy and configure network elements via this API. In turn, the northbound API presents a network abstraction to these orchestration and management systems. 

If attackers could leverage a vulnerable northbound API, they would have control over the SDN infrastructure through the controller. If the SDN controller were to receive fictitious information from a rogue application or orchestration system, non-optimized network paths would be produced that could disrupt network operations, resulting in inefficient application and business processes. An attacker could also leverage these protocols and attempt to instantiate new flows that could be inadvertently pushed into network devices’ flow-table. The attacker would want to try to spoof new flows to permit specific types of traffic that should be disallowed across the network. If an attacker could create a flow that bypasses the traffic steering that forces traffic through a firewall, the attacker would have a decided advantage. If the attacker can steer traffic in their direction, they may try to leverage that capability to sniff traffic and perform a man-in-the-middle attack.'
  desc 'check', 'Review the SDN configuration verify that it is configured to authenticate received northbound API messages using a FIPS-approved message authentication code algorithm. 

FIPS-approved algorithms for authentication are the cipher-based message authentication code (CMAC) and the keyed-hash message authentication code (HMAC). AES and 3DES are NIST-approved CMAC algorithms. The following are NIST-approved HMAC algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256. 

If the SDN controller is not configured to authenticate northbound API messages received from business applications and management systems using a FIPS-approved message authentication code algorithm, this is a finding.'
  desc 'fix', 'Configure the SDN controller to authenticate received northbound API messages using a FIPS-approved message authentication code algorithm. 

FIPS-approved algorithms for authentication are the CMAC and the HMAC. 

AES and 3DES are NIST-approved CMAC algorithms. The following are NIST-approved HMAC algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.'
  impact 0.7
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80519r1_chk'
  tag severity: 'high'
  tag gid: 'V-80783'
  tag rid: 'SV-95493r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001025'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87637r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
