control 'SV-87733' do
  title 'Northbound API traffic must traverse an out-of-band path or be encrypted using a FIPS-validated cryptographic module.'
  desc 'The SDN controller receives network service requests from orchestration and management systems to deploy and configure network elements via the northbound API. In turn, the northbound API presents a network abstraction to these systems. If either the orchestration or management system were breached, a rogue user could make modifications to the business or security policy that could disrupt network operations, resulting in inefficient application and business processes and bypassing security controls. 

In addition, invalid network service requests could be processed that could exhaust compute, storage, and network resources, leaving no resources available for legitimate business requirements. Hence, it is imperative that all southbound API traffic is secured by encrypting the traffic or deploying an out-of-band network for this traffic to traverse.'
  desc 'check', 'Determine if the northbound API traffic between the SDN controllers and the SDN management/orchestration systems traverses an out-of-band path. 

If not, verify that the northbound API traffic is encrypted using a FIPS-validated cryptographic module.

If the northbound API traffic does not traverse an out-of-band path or is not encrypted using a FIPS-validated cryptographic module, this is a finding.

Note: An out-of-band path would be a path between two nodes that traverses one or more links on an out-of-band network; that is, a dedicated layer 2 infrastructure separate from a production network.'
  desc 'fix', "Deploy an out-of-band network to provision paths between the SDN controllers and the SDN management/orchestration systems for providing transport for northbound API traffic. 

An alternative is to encrypt all northbound API traffic using a FIPS-validated cryptographic module. Implement a cryptographic module which has a validation certification and is listed on the NIST Cryptographic Module Validation Program's (CMVP) validation list."
  impact 0.7
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73215r1_chk'
  tag severity: 'high'
  tag gid: 'V-73081'
  tag rid: 'SV-87733r1_rule'
  tag stig_id: 'NET-SDN-005'
  tag gtitle: 'NET-SDN-005'
  tag fix_id: 'F-79527r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
