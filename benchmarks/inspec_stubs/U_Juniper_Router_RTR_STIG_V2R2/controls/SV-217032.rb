control 'SV-217032' do
  title 'The Juniper perimeter router must be configured to block inbound packets with source Bogon IP address prefixes.'
  desc 'Packets with Bogon IP source addresses should never be allowed to traverse the IP core. Bogon IP networks are RFC1918 addresses or address blocks that have never been assigned by the IANA or have been reserved.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the router configuration to verify that an ingress filter applied to all external interfaces is blocking packets with Bogon source addresses.

Verify a prefix list has been configured containing the current Bogon prefixes as shown in the example below.

policy-options {
    prefix-list BOGON_PREFIXES {
        0.0.0.0/8;
        10.0.0.0/8;
        100.64.0.0/10;
        127.0.0.0/8;
        169.254.0.0/16;
        172.16.0.0/12;
        192.0.0.0/24;
        192.0.2.0/24;
        192.168.0.0/16;
        198.18.0.0/15;
        198.51.100.0/24;
        203.0.113.0/24;
        224.0.0.0/4;
        240.0.0.0/4;
    }
}

Verify that the inbound filter applied to all external interfaces will block all traffic from Bogon source addresses.

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
…
…
…
firewall {
    family inet {
        filter INBOUND_FILTER {
            term BLOCK_BOGONS {
                from {
                    source-prefix-list {
                        BOGON_PREFIXES;
                    }
                }
                then {
                    syslog;
                    discard;
                }
            }
            term ALLOW_BGP {
                from {
                    protocol tcp;
                    destination-port bgp;
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

External Interfaces connected to the NIPRNet or SIPRNet

Review the inbound ACLs on external facing interfaces attached to the NIPRnet or SIPRnet to validate access control lists are configured to block inbound packets with IP sources addresses as documented in RFC5735 and RFC6598. 


External Interfaces connected to a commercial ISP or other non-DoD network
Review the inbound ACLs on external facing interfaces validate access control lists are configured to block inbound packets with IP sources addresses as documented in RFC5735 and RFC6598, as well as address space that has been allocated to the RIRs but not assigned by the RIR to an ISP or other enterprise network. The full list of bogons can be found at the following link: https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt

If the router is not configured to block inbound packets with source Bogon IP address prefixes, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the perimeter to block inbound packets with Bogon source addresses.

Configure a prefix list containing the current Bogon prefixes as shown below.

[edit policy-options]
set prefix-list BOGON_PREFIXES 0.0.0.0/8
set prefix-list BOGON_PREFIXES 10.0.0.0/8
set prefix-list BOGON_PREFIXES 100.64.0.0/10
set prefix-list BOGON_PREFIXES 127.0.0.0/8
set prefix-list BOGON_PREFIXES 169.254.0.0/16
set prefix-list BOGON_PREFIXES 172.16.0.0/12
set prefix-list BOGON_PREFIXES 192.0.0.0/24
set prefix-list BOGON_PREFIXES 192.0.2.0/24
set prefix-list BOGON_PREFIXES 192.168.0.0/16
set prefix-list BOGON_PREFIXES 198.18.0.0/15
set prefix-list BOGON_PREFIXES 198.51.100.0/24
set prefix-list BOGON_PREFIXES 203.0.113.0/24
set prefix-list BOGON_PREFIXES 224.0.0.0/4
set prefix-list BOGON_PREFIXES 240.0.0.0/4

Add a term to the inbound filter to block the Bogon prefixes.

[edit firewall family inet filter INBOUND_FILTER]
set term BLOCK_BOGONS from source-prefix-list BOGON_PREFIXES
set term BLOCK_BOGONS then syslog discard
insert term BLOCK_BOGONS before term ALLOW_BGP'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18261r296964_chk'
  tag severity: 'medium'
  tag gid: 'V-217032'
  tag rid: 'SV-217032r639663_rule'
  tag stig_id: 'JUNI-RT-000270'
  tag gtitle: 'SRG-NET-000364-RTR-000110'
  tag fix_id: 'F-18259r296965_fix'
  tag 'documentable'
  tag legacy: ['V-90849', 'SV-101059']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
