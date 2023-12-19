control 'SV-87727' do
  title 'Northbound API traffic received by the SDN controller must be authenticated using a FIPS-approved message authentication code algorithm.'
  desc 'The SDN controller determines how traffic should flow through physical and virtual network devices based on application profiles, network infrastructure resources, security policies, and business requirements that it receives via the northbound API. It also receives network service requests from orchestration and management systems to deploy and configure network elements via this API. In turn, the northbound API presents a network abstraction to these orchestration and management systems. 

If attackers could leverage a vulnerable northbound API, they would have control over the SDN infrastructure through the controller by inserting polices. If the SDN controller were to receive fictitious information from a rogue application or orchestration system, non-optimized network paths would be produced that could disrupt network operations, resulting in inefficient application and business processes. Hence, it is imperative that all northbound API traffic received by the SDN controller is authenticated.'
  desc 'check', 'Review the configuration of the SDN controllers and verify that the northbound API messages received are authenticated using a FIPS-approved message authentication code algorithm. 

FIPS-approved algorithms for authentication are the cipher-based message authentication code (CMAC) and the keyed-hash message authentication code (HMAC). 

AES and 3DES are NIST-approved CMAC algorithms. The following are NIST-approved HMAC algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256. 

If the SDN controllers do not authenticate received northbound API messages using a FIPS-approved message authentication code algorithm, this is a finding.'
  desc 'fix', 'Configure all SDN controllers to authenticate received northbound API messages using a FIPS-approved message authentication code algorithm. 

FIPS-approved algorithms for authentication are the CMAC and the HMAC. 

AES and 3DES are NIST-approved CMAC algorithms. The following are NIST-approved HMAC algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.'
  impact 0.7
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73209r1_chk'
  tag severity: 'high'
  tag gid: 'V-73075'
  tag rid: 'SV-87727r1_rule'
  tag stig_id: 'NET-SDN-002'
  tag gtitle: 'NET-SDN-002'
  tag fix_id: 'F-79521r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
