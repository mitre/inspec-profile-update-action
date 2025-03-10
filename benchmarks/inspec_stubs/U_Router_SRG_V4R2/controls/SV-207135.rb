control 'SV-207135' do
  title 'The perimeter router must be configured to filter traffic destined to the enclave in accordance with the guidelines contained in DoD Instruction 8551.1.'
  desc 'Vulnerability assessments must be reviewed by the System Administrator, and protocols must be approved by the Information Assurance (IA) staff before entering the enclave.

Access control lists (ACLs) are the first line of defense in a layered security approach. They permit authorized packets and deny unauthorized packets based on port or service type. They enhance the posture of the network by not allowing packets to reach a potential target within the security domain. The lists provided are highly susceptible ports and services that should be blocked or limited as much as possible without adversely affecting customer requirements. Auditing packets attempting to penetrate the network but that are stopped by an ACL will allow network administrators to broaden their protective ring and more tightly define the scope of operation.

If the perimeter is in a Deny-by-Default posture and what is allowed through the filter is in accordance with DoD Instruction 8551.1, and if the permit rule is explicitly defined with explicit ports and protocols allowed, then all requirements related to PPS being blocked would be satisfied.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone. 

Review the router configuration to verify that the ingress filter is in accordance with DoD 8551. 

If the router does not filter traffic in accordance with the guidelines contained in DoD 8551, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the router to use ingress ACLs to restrict traffic in accordance with the guidelines contained in DOD Instruction 8551.1 for all services and protocols required for operational commitments.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7396r382343_chk'
  tag severity: 'medium'
  tag gid: 'V-207135'
  tag rid: 'SV-207135r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000003'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7396r539636_fix'
  tag 'documentable'
  tag legacy: ['V-78243', 'SV-92949']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
