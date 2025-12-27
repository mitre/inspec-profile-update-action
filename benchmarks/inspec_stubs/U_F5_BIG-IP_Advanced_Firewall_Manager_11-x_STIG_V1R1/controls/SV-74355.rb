control 'SV-74355' do
  title 'The BIG-IP AFM module must be configured to only allow incoming communications from authorized sources routed to authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Access control policies and access control lists implemented on devices that control the flow of network traffic (e.g., application-level firewalls and Web content filters) ensure the flow of traffic is only allowed from authorized sources to authorized destinations. Networks with different levels of trust (e.g., the Internet or CDS) must be kept separate.'
  desc 'check', 'If the BIG-IP AFM module is not used to support user access control intermediary services for virtual servers, this is not applicable.

Verify the BIG-IP AFM module is configured to only allow incoming communications from authorized sources routed to authorized destinations.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select the applicable Virtual Servers(s) from the list to verify.

Navigate to the Security >> Policies tab.

Verify that "Network Firewall" is assigned a local Network Firewall Policy.

Verify configuration of the identified Network Firewall policy:

Navigate to the BIG-IP System manager >> Security >> Network Firewall >> Active Rules.

Select the  Network Firewall policy that was assigned to the Virtual Server.

Review the configuration of the "Protocol", "Source", "Destination", and "Action" sections at a minimum to ensure that the policy is only allowing incoming communications from authorized sources enroute to authorized destinations.

If the BIG-IP AFM module is not configured to only allow incoming communications from unauthorized sources routed to unauthorized destinations, this is a finding.'
  desc 'fix', 'Configure the BIG-IP AFM module to only allow incoming communications from authorized sources routed to authorized destinations.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP AFM 11.x'
  tag check_id: 'C-60615r1_chk'
  tag severity: 'medium'
  tag gid: 'V-59925'
  tag rid: 'SV-74355r1_rule'
  tag stig_id: 'F5BI-AF-000223'
  tag gtitle: 'SRG-NET-000364-ALG-000122'
  tag fix_id: 'F-65335r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
