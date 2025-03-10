control 'SV-234147' do
  title 'The FortiGate firewall must filter traffic destined to the internal enclave in accordance with the specific traffic that is approved and registered in the Ports, Protocols, and Services Management (PPSM) Category Assurance List (CAL), Vulnerability Assessments (VAs) for that the enclave.'
  desc "The enclave's internal network contains the servers where mission-critical data and applications reside. Malicious traffic can enter from an external boundary or originate from a compromised host internally.

Vulnerability assessments must be reviewed by the SA and protocols must be approved by the IA staff before entering the enclave. 

Firewall filters (e.g., rules, access control lists [ACLs], screens, and policies) are the first line of defense in a layered security approach. They permit authorized packets and deny unauthorized packets based on port or service type. They enhance the posture of the network by not allowing packets to even reach a potential target within the security domain. The filters provided are highly susceptible ports and services that should be blocked or limited as much as possible without adversely affecting customer requirements. Auditing packets attempting to penetrate the network but stopped by the firewall filters will allow network administrators to broaden their protective ring and more tightly define the scope of operation. 

If the perimeter is in a deny-by-default posture and what is allowed through the filter is in accordance with the PPSM CAL and VAs for the enclave, and if the permit rule is explicitly defined with explicit ports and protocols allowed, then all requirements related to the database being blocked would be satisfied."
  desc 'check', 'Log in to the FortiGate GUI with Super-Admin privilege.

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # show firewall policy
     # show firewall policy6

Ensure policies are created that only allow approved traffic that is in accordance with the PPSM CAL and VAs for the enclave. 

If configured policies allow traffic that is not allowed per the PPSM CAL and VAs for the enclave, this is a finding.'
  desc 'fix', 'Log in to the FortiGate GUI with Super-Admin privilege.
1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Click +Create New.
4. Name the policy, select Incoming and Outgoing Interfaces.
5. Create policies with authorized sources and destinations.
6. Set action to ACCEPT.
7. Ensure the Enable this policy is toggled to right.
8. Click OK.
9. Ensure a policy is created for each interface.

Traffic is denied by default and policies must be configured to allow traffic that meets PPSM CAL and VA guidelines.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37332r611439_chk'
  tag severity: 'medium'
  tag gid: 'V-234147'
  tag rid: 'SV-234147r628789_rule'
  tag stig_id: 'FNFG-FW-000085'
  tag gtitle: 'SRG-NET-000205-FW-000040'
  tag fix_id: 'F-37297r611440_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
