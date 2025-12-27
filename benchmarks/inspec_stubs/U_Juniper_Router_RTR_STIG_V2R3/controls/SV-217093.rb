control 'SV-217093' do
  title 'The Juniper Multicast Source Discovery Protocol (MSDP) router must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'MSDP peering with customer network routers presents additional risks to the DISN Core, whether from a rogue or misconfigured MSDP-enabled router. To guard against an attack from malicious MSDP traffic, the receive path or interface filter for all MSDP-enabled RP routers must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'check', 'Review the router configuration to determine if there is a receive path or interface filter to only accept MSDP packets from known MSDP peers.

Verify that the loopback has been configured to filter packets destined to the routing engine as shown in the example below.

interfaces {
    …
    …
    …
    }
    lo0 {
        unit 0 {
            family inet {
                filter {
                    input PROTECT_RE;
                }
                address 2.2.2.2/32;
            }
        }
    }
}

Verify that the filter is configured to only accept MSDP packets from known MSDP peers as shown in the example below.

firewall {
    family inet {
        filter PROTECT_RE {
            term MSDP_PEERS {
                from {
                    source-address {
                        0.0.0.0/0;
                        1.1.1.1/32 except;
                        5.5.5.5/32 except;
                    }
                    protocol tcp;
                    port msdp;
                }
                then {
                    discard;
                }
            }
            term ALLOW_OTHER {
                then accept;
            }
        }
    }
}

If the router is not configured to only accept MSDP packets from known MSDP peers, this is a finding.'
  desc 'fix', 'Configure the receive path filter to only accept MSDP packets from known MSDP peers as shown in the following example:

[edit firewall family inet filter PROTECT_RE]
set term MSDP_PEERS from protocol tcp port msdp
set term MSDP_PEERS from source-address 0.0.0.0/0
set term MSDP_PEERS from source-address 1.1.1.1/32 except
set term MSDP_PEERS from source-address 5.5.5.5/32 except
set term MSDP_PEERS then discard
set term ALLOW_OTHER then accept

Apply the filter to the loopback interface.

[edit interfaces lo0 unit 0 family inet]
set filter input PROTECT_RE'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18322r297147_chk'
  tag severity: 'medium'
  tag gid: 'V-217093'
  tag rid: 'SV-217093r604135_rule'
  tag stig_id: 'JUNI-RT-000890'
  tag gtitle: 'SRG-NET-000364-RTR-000116'
  tag fix_id: 'F-18320r297148_fix'
  tag 'documentable'
  tag legacy: ['SV-101179', 'V-90969']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
