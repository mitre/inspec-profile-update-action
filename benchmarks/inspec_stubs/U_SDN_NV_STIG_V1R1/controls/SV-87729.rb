control 'SV-87729' do
  title 'Access to the SDN management and orchestration systems must be authenticated using a FIPS-approved message authentication code algorithm.'
  desc 'The SDN controller receives network service requests from orchestration and management systems to deploy and configure network elements via the northbound API. In turn, the Northbound API presents a network abstraction to these systems. If either the orchestration or management system were breached, a rogue user could make modifications to the business or security policy that could disrupt network operations, resulting in inefficient application and business processes as well as bypassing security controls. 

In addition, invalid network service requests could be processed that could exhaust compute, storage, and network resources, leaving no resources available for legitimate business requirements.'
  desc 'check', 'Review all management and orchestration systems within the SDN framework and verify that access to these components requires DOD PKI certificate-based authentication. 

If access to the SDN management and orchestration systems does not require DOD PKI certificate-based authentication, this is a finding.'
  desc 'fix', 'Configure all management and orchestration systems within the SDN framework to require DOD PKI certificate-based authentication for access.'
  impact 0.5
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73211r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73077'
  tag rid: 'SV-87729r1_rule'
  tag stig_id: 'NET-SDN-003'
  tag gtitle: 'NET-SDN-003'
  tag fix_id: 'F-79523r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
