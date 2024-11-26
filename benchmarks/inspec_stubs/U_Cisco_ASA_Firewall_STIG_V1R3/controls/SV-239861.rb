control 'SV-239861' do
  title 'The Cisco ASA perimeter firewall must be configured to filter traffic destined to the enclave in accordance with the specific traffic that is approved and registered in the Ports, Protocols, and Services Management (PPSM)  Category Assurance List (CAL) and vulnerability assessments.'
  desc "The enclave's internal network contains the servers where mission-critical data and applications reside. Malicious traffic can enter from an external boundary or originate from a compromised host internally.

Vulnerability assessments must be reviewed by the SA and protocols must be approved by the IA staff before entering the enclave. 

Firewall filters (e.g., rules, access control lists [ACLs], screens, and policies) are the first line of defense in a layered security approach. They permit authorized packets and deny unauthorized packets based on port or service type. They enhance the posture of the network by not allowing packets to even reach a potential target within the security domain. The filters provided are highly susceptible ports and services that should be blocked or limited as much as possible without adversely affecting customer requirements. Auditing packets attempting to penetrate the network but stopped by the firewall filters will allow network administrators to broaden their protective ring and more tightly define the scope of operation. 

If the perimeter is in a Deny-by-Default posture and what is allowed through the filter is in accordance with the PPSM CAL and VAs for the enclave, and if the permit rule is explicitly defined with explicit ports and protocols allowed, then all requirements related to the database being blocked would be satisfied."
  desc 'check', 'Review the inbound ACL to verify the ports and services allowed are in accordance with the PPSM CAL.

Review the ASA configuration to determine if it only permits inbound traffic using authorized ports and services.

Step 1: Verify that an ingress ACL has been applied to the external interface as shown in the example below.

 interface GigabitEthernet0/0
 nameif OUTSIDE
 security-level 0
 ip address x.1.11.1 255.255.255.0
…
…
…
access-group OUTSIDE_IN in interface OUTSIDE

Step 2: Verify that the ingress ACL only allows inbound traffic in accordance with the PPSM CAL as shown in the example below.

access-list OUTSIDE_IN extended permit tcp any any eq www 
access-list OUTSIDE_IN extended permit tcp any any eq https 
access-list OUTSIDE_IN extended permit tcp any any eq domain 
access-list OUTSIDE_IN extended permit tcp any any eq ftp 
access-list OUTSIDE_IN extended permit tcp any any eq ftp-data 
access-list OUTSIDE_IN extended permit udp any any eq sip 
access-list OUTSIDE_IN extended deny ip any any log

If the ASA is not configured to only allow inbound traffic in accordance with the PPSM CAL, this is a finding.'
  desc 'fix', 'Step 1: Configure the ingress ACL similar to the example below.

ASA(config)# access-list OUTSIDE_IN extended permit tcp any any eq https
ASA(config)# access-list OUTSIDE_IN extended permit tcp any any eq http
ASA(config)# access-list OUTSIDE_IN extended permit tcp any any eq domain
ASA(config)# access-list OUTSIDE_IN extended permit tcp any any eq ftp   
ASA(config)# access-list OUTSIDE_IN extended permit tcp any any eq ftp-data
ASA(config)# access-list OUTSIDE_IN extended permit udp any any eq sip
ASA(config)# access-list OUTSIDE_IN extended deny ip any any log      

Step 2: Apply the ACL inbound on the external interface as shown in the example below.

ASA(config)# access-group OUTSIDE_IN in interface OUTSIDE 
ASA(config)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA Firewall'
  tag check_id: 'C-43094r665867_chk'
  tag severity: 'medium'
  tag gid: 'V-239861'
  tag rid: 'SV-239861r665904_rule'
  tag stig_id: 'CASA-FW-000170'
  tag gtitle: 'SRG-NET-000205-FW-000040'
  tag fix_id: 'F-43053r665868_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
