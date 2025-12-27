control 'SV-95495' do
  title 'The SDN controller must be configured to encrypt all southbound Application Program Interface (API) control-plane messages using a FIPS-validated cryptographic module.'
  desc 'Southbound APIs such as OpenFlow provide the forwarding tables to network devices, such as switches and routers, both physical and virtual (hypervisor-based). The SDN controllers use the concept of flows to identify network traffic based on predefined rules that can be statically or dynamically programmed by the SDN control software, thereby determining how traffic should flow through network devices based on usage patterns, applications, and policy that can optimize traffic paths based on business requirements and not network infrastructure design. 

An attacker could also leverage these protocols and attempt to instantiate new flows into a device’s flow-table. The attacker would want to try to spoof new flows to permit specific types of traffic that should be disallowed across the network. If an attacker could create a flow that bypasses the traffic steering that forces traffic through a firewall, the attacker would have a decided advantage. If an SDN-aware router or switch received erroneous forwarding information from a rogue controller, traffic could be black-holed or even forwarded to a malicious user to sniff traffic and perform a man-in-the-middle attack. Hence, it is imperative to secure flow table updates by encrypting all southbound API traffic or deploying an out-of-band network for this traffic to traverse.'
  desc 'check', "Determine if the southbound API control-plane traffic traverses an out-of-band path. If not, review the SDN controller configuration to verify that southbound API management-plane traffic is encrypted using a using a FIPS-validated cryptographic module. 

If the southbound API control-plane traffic does not traverse an out-of-band path or is not encrypted using a using a FIPS-validated cryptographic module, this is a finding.

Note: FIPS-validated cryptographic modules are listed on the NIST Cryptographic Module Validation Program's (CMVP) validation list."
  desc 'fix', "Deploy an out-of-band network to provision paths between SDN controller and SDN-enabled devices as well as all hypervisor hosts that compose the SDN infrastructure to provide transport for southbound API control-plane traffic. 

An alternative is to configure the SDN controller to encrypt all southbound API control-plane traffic using a using a FIPS-validated cryptographic module. Implement a cryptographic module which has a validation certification and is listed on the NIST Cryptographic Module Validation Program's (CMVP) validation list."
  impact 0.7
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80521r1_chk'
  tag severity: 'high'
  tag gid: 'V-80785'
  tag rid: 'SV-95495r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001030'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87639r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
