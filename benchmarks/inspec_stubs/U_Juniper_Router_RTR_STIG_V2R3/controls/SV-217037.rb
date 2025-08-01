control 'SV-217037' do
  title 'The Juniper perimeter router must be configured to filter traffic destined to the enclave in accordance with the guidelines contained in DoD Instruction 8551.1.'
  desc 'Vulnerability assessments must be reviewed by the System Administrator, and protocols must be approved by the Information Assurance (IA) staff before entering the enclave.

Access control lists (ACLs) are the first line of defense in a layered security approach. They permit authorized packets and deny unauthorized packets based on port or service type. They enhance the posture of the network by not allowing packets to reach a potential target within the security domain. The lists provided are highly susceptible ports and services that should be blocked or limited as much as possible without adversely affecting customer requirements. Auditing packets attempting to penetrate the network but that are stopped by an ACL will allow network administrators to broaden their protective ring and more tightly define the scope of operation.

If the perimeter is in a Deny-by-Default posture and what is allowed through the filter is in accordance with DoD Instruction 8551.1, and if the permit rule is explicitly defined with explicit ports and protocols allowed, then all requirements related to PPS being blocked would be satisfied.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the router configuration to verify that the ingress filter is in accordance with DoD 8551.

Verify that an inbound filter is configured on all external interfaces.

interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter {
                    input INBOUND_FILTER;
                }
                address 11.1.12.2/24;
            }
        }
    }

Review the inbound filter to verify that it is filtering traffic in accordance with DoD 8551.

firewall {
    family inet {
        filter INBOUND_FILTER {
            term ALLOW_ABC {
                from {
                    protocol tcp;
                    destination-port abc;
                }
                then accept;
            }
            term ALLOW_XYZ {
                from {
                    protocol xyz;
                }
                then accept;
            }
            term DENY_ALL_OTHER {
                then {
                    syslog;
                    reject;
                }
            }
        }
}

If the router does not filter traffic in accordance with the guidelines contained in DoD 8551, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the router to use an inbound filter on all external interfaces as shown in the example below to restrict traffic in accordance with the guidelines contained in DOD Instruction 8551.1.

set filter INBOUND_FILTER term ALLOW_ABC from protocol tcp destination-port abc
set filter INBOUND_FILTER term ALLOW_ABC then accept
set filter INBOUND_FILTER term ALLOW_XYZ from protocol tcp destination-port xyz
set filter INBOUND_FILTER term ALLOW_XYZ then accept
set filter INBOUND_FILTER term DENY_ALL_OTHER then syslog reject

[edit interfaces ge-0/0/0 unit 0 family inet]
set filter input INBOUND_FILTER'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18266r296979_chk'
  tag severity: 'medium'
  tag gid: 'V-217037'
  tag rid: 'SV-217037r604135_rule'
  tag stig_id: 'JUNI-RT-000320'
  tag gtitle: 'SRG-NET-000205-RTR-000003'
  tag fix_id: 'F-18264r296980_fix'
  tag 'documentable'
  tag legacy: ['SV-101069', 'V-90859']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
