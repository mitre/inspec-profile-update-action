control 'SV-68883' do
  title 'The ALG must only allow incoming communications from organization-defined authorized sources routed to organization-defined authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic which poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Access control policies and access control lists implemented on devices that control the flow of network traffic (e.g., application level firewalls and Web content filters), ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet or CDS) must be kept separate.'
  desc 'check', 'Verify the ALG only allows incoming communications from organization-defined authorized sources routed to organization-defined authorized destinations.

If the ALG allows incoming communications from unauthorized sources routed to unauthorized destinations, this is a finding.'
  desc 'fix', 'Configure the ALG to only allow incoming communications from organization-defined authorized sources routed to organization-defined authorized destinations.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55257r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54637'
  tag rid: 'SV-68883r1_rule'
  tag stig_id: 'SRG-NET-000364-ALG-000122'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-59493r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
