control 'SV-87731' do
  title 'Southbound API control plane traffic must traverse an out-of-band path or be encrypted using a FIPS-validated cryptographic module.'
  desc 'Southbound APIs such as OpenFlow provide the forwarding tables to network devices such as switches and routers, both physical and virtual (hypervisor-based). The SDN controllers use the concept of flows to identify network traffic based on predefined rules that can be statically or dynamically programmed by the SDN control software, thereby determining how traffic should flow through network devices based on usage patterns, applications, and policy that can optimize traffic paths based on business requirements and not network infrastructure design. 

If an SDN-aware router or switch received erroneous forwarding information from a rogue controller, traffic could be black-holed or even forwarded to a malicious user to sniff traffic and perform a man-in-the-middle attack. Hence, it is imperative to secure flow table updates by encrypting all southbound API traffic or deploying an out-of-band network for this traffic to traverse.'
  desc 'check', 'Determine if the southbound API control plane traffic between the SDN controllers and the SDN-enabled network elements traverses an out-of-band path. 

If not, verify that the southbound API traffic is encrypted using a FIPS-validated cryptographic module.

If the southbound API traffic does not traverse an out-of-band path or is not encrypted using a FIPS-validated cryptographic module, this is a finding.

Note: An out-of-band path would be a path between two nodes that traverses one or more links on an out-of-band network; that is, a dedicated layer 2 infrastructure separate from a production network.'
  desc 'fix', "Deploy an out-of-band network to provision paths between the SDN controllers and the SDN-enabled network elements for providing transport for southbound API control plane traffic.

An alternative is to encrypt all southbound API control plane traffic using a FIPS-validated cryptographic module. Implement a cryptographic module which has a validation certification and is listed on the NIST Cryptographic Module Validation Program's (CMVP) validation list."
  impact 0.7
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73213r1_chk'
  tag severity: 'high'
  tag gid: 'V-73079'
  tag rid: 'SV-87731r1_rule'
  tag stig_id: 'NET-SDN-004'
  tag gtitle: 'NET-SDN-004'
  tag fix_id: 'F-79525r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
