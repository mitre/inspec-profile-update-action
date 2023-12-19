control 'SV-95491' do
  title 'The SDN controller must be configured to authenticate southbound Application Program Interface (API) control-plane messages received from SDN-enabled network elements using a FIPS-approved message authentication code algorithm.'
  desc 'Southbound APIs such as OpenFlow provide the forwarding tables to network devices, such as switches and routers, both physical and virtual (hypervisor-based). The SDN controllers use the concept of flows to identify network traffic based on predefined rules that can be statically or dynamically programmed by the SDN control software, thereby determining how traffic should flow through network devices based on usage patterns, applications, and policy that can optimize traffic paths based on business requirements and not network infrastructure design. The SDN controller can receive control-plane messages from the SDN-enabled routers and switches to provide link state information or to require a flow table entry for a packet that does not map to any entries (i.e., reactive flow setup). To ensure the integrity and authenticity of these messages, it is imperative that they are authenticated prior to processing and taking any action.'
  desc 'check', 'Review the SDN configuration, verify that it is configured to authenticate received southbound API control-plane messages using a FIPS-approved message authentication code algorithm. 

FIPS-approved algorithms for authentication are the cipher-based message authentication code (CMAC) and the keyed-hash message authentication code (HMAC). AES and 3DES are NIST-approved CMAC algorithms. The following are NIST-approved HMAC algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256. 

If the SDN controller is not configured to authenticate received southbound API control-plane messages using a FIPS-approved message authentication code algorithm, this is a finding.'
  desc 'fix', 'Configure the SDN controller to authenticate southbound API control-plane messages using a FIPS-approved message authentication code algorithm. 

FIPS-approved algorithms for authentication are the CMAC and the HMAC. AES and 3DES are NIST-approved CMAC algorithms. The following are NIST-approved HMAC algorithms: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, and SHA-512/256.'
  impact 0.7
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80517r1_chk'
  tag severity: 'high'
  tag gid: 'V-80781'
  tag rid: 'SV-95491r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001020'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87635r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
