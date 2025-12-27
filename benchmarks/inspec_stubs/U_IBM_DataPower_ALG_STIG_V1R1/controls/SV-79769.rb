control 'SV-79769' do
  title 'The DataPower Gateway must only allow incoming communications from organization-defined authorized sources routed to organization-defined authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic which poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Access control policies and access control lists implemented on devices that control the flow of network traffic (e.g., application level firewalls and Web content filters), ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet or CDS) must be kept separate.'
  desc 'check', 'Type “Access Control List” in nav search. Verify that Access Control Lists are used for all services. If Access Control lists are not used, this is a finding.'
  desc 'fix', 'Type “Access Control List” in nav search. Create ACL with desired address ranges and gates. Apply this ACL to all Front Side Handlers or Firewalls.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65907r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65279'
  tag rid: 'SV-79769r1_rule'
  tag stig_id: 'WSDP-AG-000103'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-71219r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
