control 'SV-95497' do
  title 'The SDN controller must be configured to encrypt all northbound Application Program Interface (API) messages using a FIPS-validated cryptographic module.'
  desc 'The SDN controller receives network service requests from orchestration and management systems to deploy and configure network elements via the northbound API. In turn, the northbound API presents a network abstraction to these systems. If either the orchestration or management system were breached, a rogue user could make modifications to the business or security policy that could disrupt network operations, resulting in inefficient application and business processes and bypassing security controls. In addition, invalid network service requests could be processed that could exhaust compute, storage, and network resources, leaving no resources available for legitimate business requirements. Hence, it is imperative that all northbound API traffic is secured by encrypting the traffic or deploying an out-of-band network for this traffic to traverse.'
  desc 'check', "Determine if the northbound API traffic traverses an out-of-band path. If not, review the SDN controller configuration to verify that northbound API traffic is encrypted using a using a FIPS-validated cryptographic module. 

If northbound API traffic does not traverse an out-of-band path and is not encrypted using a using a FIPS-validated cryptographic module, this is a finding.

Note: FIPS-validated cryptographic modules are listed on the NIST Cryptographic Module Validation Program's (CMVP) validation list."
  desc 'fix', "Deploy an out-of-band network to provision paths between the SDN controller and the SDN management/orchestration systems for providing transport for northbound API traffic. 

An alternative is to configure the SDN controller to encrypt all northbound API traffic using a FIPS-validated cryptographic module. Implement a cryptographic module which has a validation certification and is listed on the NIST Cryptographic Module Validation Program's (CMVP) validation list."
  impact 0.7
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80523r1_chk'
  tag severity: 'high'
  tag gid: 'V-80787'
  tag rid: 'SV-95497r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001035'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87641r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
