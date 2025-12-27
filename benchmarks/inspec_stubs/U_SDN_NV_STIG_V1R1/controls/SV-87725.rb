control 'SV-87725' do
  title 'Southbound API control plane traffic between the SDN controller and SDN-enabled network elements must be mutually authenticated using a FIPS-approved message authentication code algorithm.'
  desc 'Southbound APIs such as OpenFlow provide the forwarding tables to network devices such as switches and routers, both physical and virtual (hypervisor-based). The SDN controllers use the concept of flows to identify network traffic based on predefined rules that can be statically or dynamically programmed by the SDN control software, thereby determining how traffic should flow through network devices based on usage patterns, applications, and policy that can optimize traffic paths based on business requirements and not network infrastructure design. 

If an SDN-aware router or switch received erroneous forwarding information from a rogue controller, traffic could be black-holed or even forwarded to a malicious user to sniff traffic and perform a man-in-the-middle attack. Hence, it is imperative that mutual authentication is enabled between the SDN controller and the SDN-aware network elements for all southbound API traffic.'
  desc 'check', 'Review the components within the SDN framework that send and receive southbound API messages and verify that the messages are authenticated using a FIPS-approved message authentication code algorithm. 

FIPS-approved algorithms for authentication are the cipher-based message authentication code (CMAC) and the keyed-hash message authentication code (HMAC). 

AES and 3DES are NIST-approved CMAC algorithms. The following are NIST-approved HMAC algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256. 

If the SDN controller or SDN-enabled network elements do not authenticate received southbound API messages using a FIPS-approved message authentication code algorithm, this is a finding.'
  desc 'fix', 'Ensure that all components within the SDN framework authenticate southbound API messages using a FIPS-approved message authentication code algorithm. 

FIPS-approved algorithms for authentication are the CMAC and the HMAC. 

AES and 3DES are NIST-approved CMAC algorithms. The following are NIST-approved HMAC algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.'
  impact 0.7
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73207r1_chk'
  tag severity: 'high'
  tag gid: 'V-73073'
  tag rid: 'SV-87725r1_rule'
  tag stig_id: 'NET-SDN-001'
  tag gtitle: 'NET-SDN-001'
  tag fix_id: 'F-79519r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
