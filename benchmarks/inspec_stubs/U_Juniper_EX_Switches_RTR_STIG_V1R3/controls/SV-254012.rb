control 'SV-254012' do
  title 'The Juniper perimeter router must be configured to filter traffic destined to the enclave in accordance with the guidelines contained in DoD Instruction 8551.1.'
  desc 'Vulnerability assessments must be reviewed by the System Administrator, and protocols must be approved by the Information Assurance (IA) staff before entering the enclave.

Stateless firewall filters are the first line of defense in a layered security approach. They permit authorized packets and deny unauthorized packets based on port or service type. They enhance the posture of the network by not allowing packets to reach a potential target within the security domain. The lists provided are highly susceptible ports and services that should be blocked or limited as much as possible without adversely affecting customer requirements. Auditing packets attempting to penetrate the network but that are stopped by a firewall filter will allow network administrators to broaden their protective ring and more tightly define the scope of operation.

If the perimeter is in a Deny-by-Default posture and what is allowed through the filter is in accordance with DoD Instruction 8551.1, and if the permit rule is explicitly defined with explicit ports and protocols allowed, then all requirements related to PPS being blocked would be satisfied.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to verify that the ingress filter is in accordance with DoD 8551. For example, assuming TCP 80 and 443 are permitted inbound:
[edit policy-options]
prefix-list inside-addresses-ipv4 {
    <interior IPv4 subnet / mask>;
}
prefix-list inside-addresses-ipv4 {
    <interior IPv6 subnet / prefix>;
}
[edit firewall]
family inet {
    filter inbound-ipv4 {
        term 1 {
            from {
                destination-prefix-list inside-addresses-ipv4;
                protocol tcp;
                destination-port [ 80 443 ];
            }
            then accept;
        }
        <other terms as required>
        term default-deny {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}
family inet6 {
    filter inbound-ipv6 {
        term 1 {
            from {
                destination-prefix-list inside-addresses-ipv6;
                next-header tcp;
                destination-port [ 80 443 ];
            }
            then accept;
        }
        <other terms as required>
        term default-deny {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}

If the router does not filter traffic in accordance with the guidelines contained in DoD 8551, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to use ingress firewall filters to restrict traffic in accordance with the guidelines contained in DOD Instruction 8551.1 for all services and protocols required for operational commitments.

set policy-options prefix-list inside-addresses-ipv4 <IPv4 subnet>/<mask>
<additional subnets as required>
set policy-options prefix-list inside-addresses-ipv6 <IPv6 subnet>/<prefix>
<additional subnets as required>

set firewall family inet filter inbound-ipv4 term 1 from destination-prefix-list inside-addresses-ipv4
set firewall family inet filter inbound-ipv4 term 1 from protocol tcp
set firewall family inet filter inbound-ipv4 term 1 from destination-port 80
set firewall family inet filter inbound-ipv4 term 1 from destination-port 443
set firewall family inet filter inbound-ipv4 term 1 then accept
<additional terms as required>
set firewall family inet filter inbound-ipv4 term default-deny then log
set firewall family inet filter inbound-ipv4 term default-deny then syslog
set firewall family inet filter inbound-ipv4 term default-deny then discard

set firewall family inet6 filter inbound-ipv6 term 1 from destination-prefix-list inside-addresses-ipv6
set firewall family inet6 filter inbound-ipv6 term 1 from next-header tcp
set firewall family inet6 filter inbound-ipv6 term 1 from destination-port 80
set firewall family inet6 filter inbound-ipv6 term 1 from destination-port 443
set firewall family inet6 filter inbound-ipv6 term 1 then accept
set firewall family inet6 filter inbound-ipv6 term default-deny then log
set firewall family inet6 filter inbound-ipv6 term default-deny then syslog
set firewall family inet6 filter inbound-ipv6 term default-deny then discard'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57464r844067_chk'
  tag severity: 'medium'
  tag gid: 'V-254012'
  tag rid: 'SV-254012r844069_rule'
  tag stig_id: 'JUEX-RT-000400'
  tag gtitle: 'SRG-NET-000205-RTR-000003'
  tag fix_id: 'F-57415r844068_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
