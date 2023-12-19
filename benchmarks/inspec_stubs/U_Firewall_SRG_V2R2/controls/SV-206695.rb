control 'SV-206695' do
  title 'The perimeter firewall must filter traffic destined to the internal enclave in accordance with the specific traffic that is approved and registered in the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL), Vulnerability Assessments (VAs) for that the enclave.'
  desc "The enclave's internal network contains the servers where mission-critical data and applications reside. Malicious traffic can enter from an external boundary or originate from a compromised host internally.

Vulnerability assessments must be reviewed by the SA and protocols must be approved by the IA staff before entering the enclave. 

Firewall filters (e.g., rules, access control lists [ACLs], screens, and policies) are the first line of defense in a layered security approach. They permit authorized packets and deny unauthorized packets based on port or service type. They enhance the posture of the network by not allowing packets to even reach a potential target within the security domain. The filters provided are highly susceptible ports and services that should be blocked or limited as much as possible without adversely affecting customer requirements. Auditing packets attempting to penetrate the network but stopped by the firewall filters will allow network administrators to broaden their protective ring and more tightly define the scope of operation. 

If the perimeter is in a Deny-by-Default posture and what is allowed through the filter is in accordance with the PPSM CAL and VAs for the enclave, and if the permit rule is explicitly defined with explicit ports and protocols allowed, then all requirements related to the database being blocked would be satisfied."
  desc 'check', 'Review the perimeter firewall to verify it filters traffic destined to the internal enclave in accordance with the guidelines contained in the PPSM CAL and VAs for the enclave.

If the perimeter firewall does not filter traffic destined to the internal enclave in accordance with the guidelines contained in the PPSM CAL and VAs for the enclave, this is a finding.'
  desc 'fix', 'Configure the perimeter firewall to filter traffic destined to the internal enclave in accordance with the guidelines contained in the PPSM CAL and VAs for the enclave.'
  impact 0.5
  ref 'DPMS Target Firewall'
  tag check_id: 'C-6952r297864_chk'
  tag severity: 'medium'
  tag gid: 'V-206695'
  tag rid: 'SV-206695r604133_rule'
  tag stig_id: 'SRG-NET-000205-FW-000040'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-6952r297865_fix'
  tag 'documentable'
  tag legacy: ['V-79485', 'SV-94191']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
