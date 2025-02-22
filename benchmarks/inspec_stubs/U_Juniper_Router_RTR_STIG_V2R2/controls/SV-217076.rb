control 'SV-217076' do
  title 'The Juniper PE router must be configured to block any traffic that is destined to IP core infrastructure.'
  desc 'IP/MPLS networks providing VPN and transit services must provide, at the least, the same level of protection against denial-of-service (DoS) attacks and intrusions as Layer 2 networks. Although the IP core network elements are hidden, security should never rely entirely on obscurity.

IP addresses can be guessed. Core network elements must not be accessible from any external host. Protecting the core from any attack is vital for the integrity and privacy of customer traffic as well as the availability of transit services. A compromise of the IP core can result in an outage or, at a minimum, non-optimized forwarding of customer traffic. Protecting the core from an outside attack also prevents attackers from using the core to attack any customer. Hence, it is imperative that all routers at the edge deny traffic destined to any address belonging to the IP core infrastructure.'
  desc 'check', 'Review the router configuration to verify that an ingress filter is applied to all CE-facing interfaces. 

interfaces {
    ge-0/1/0 {
        description "link to Customer 2";
        unit 0 {
            family inet {
                filter {
                    input INGRESS_FILTER;
                }
                address x.x.x.x/30;
            }
        }
    }

Verify that the ingress filter discards and logs packets destined to the IP core address space. 

firewall {
    family inet {
        filter INGRESS_FILTER {
            term BLOCK_TO_CORE {
                from {
                    destination-address {
                        x.x.x.x/8;
                    }
                }
                then {
                    log;
                    discard;
                }
            }
            term ALLOW_TRANSIT_TRAFFIC {
                then accept;
            }
        }
    }

If the PE router is not configured to block any traffic with a destination address assigned to the IP core infrastructure, this is a finding.

Note: Internet Control Message Protocol (ICMP) echo requests and traceroutes will be allowed to the edge from external adjacent neighbors.'
  desc 'fix', 'Configure protection for the IP core to be implemented at the edges by blocking any traffic with a destination address assigned to the IP core infrastructure.

Configure an ingress filter to discard and log packets destined to the IP core address space. 

[edit firewall family inet]
set filter INGRESS_FILTER term BLOCK_TO_CORE from destination-address x.x.x.x/8
set filter INGRESS_FILTER term BLOCK_TO_CORE then log discard
set filter INGRESS_FILTER term ALLOW_TRANSIT_TRAFFIC then accept

Apply the filter inbound to all CE-facing interfaces.

[edit interfaces ge-0/1/0 unit 0]
set family inet filter input INGRESS_FILTER'
  impact 0.7
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18305r297096_chk'
  tag severity: 'high'
  tag gid: 'V-217076'
  tag rid: 'SV-217076r639663_rule'
  tag stig_id: 'JUNI-RT-000710'
  tag gtitle: 'SRG-NET-000205-RTR-000007'
  tag fix_id: 'F-18303r297097_fix'
  tag 'documentable'
  tag legacy: ['V-90933', 'SV-101143']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
