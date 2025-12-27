control 'SV-217048' do
  title 'The Juniper out-of-band management (OOBM) gateway router must be configured to block any traffic destined to itself that is not sourced from the OOBM network or the NOC.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, several safeguards must be implemented for containment of management and production traffic boundaries. It is imperative that hosts from the managed network are not able to access the OOBM gateway router.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the firewall filter applied to the routers loopback interface to verify that only traffic sourced from the OOBM network or the NOC is allowed to access the router as shown in the example below.

interfaces {
…
…
…
    lo0 {
        unit 0 {
            family inet {
                filter {
                    input PROTECT_RE;
                }
                address 1.1.1.1/32;
            }
        }
    }
}
…
…
…
firewall {
    family inet {
        filter PROTECT_RE {
            term RESTRICT_ADDRESS {
                from {
                    source-address {
                        0.0.0.0/0;
                        10.2.14.0/24 except;
                    }
                }
                then {
                    syslog;
                    discard;
                }
            }
            term ALLOW_OTHER {
                then accept;
            }
        }
    }
}

If the router does not block any traffic destined to itself that is not sourced from the OOBM network or the NOC, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the router to only allow traffic to the Routing Engine from the OOBM network.

[edit firewall family inet]
set filter PROTECT_RP term RESTRICT_ADDRESS from source-address 0.0.0.0/0
set filter PROTECT_RP term RESTRICT_ADDRESS from source-address 10.2.14.0/24 except
set filter PROTECT_RP term RESTRICT_ADDRESS then syslog discard 
set filter PROTECT_RP term ALLOW_OTHER then accept 

[edit interfaces lo0 unit 0 family inet]
set filter input PROTECT_RP'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18277r297012_chk'
  tag severity: 'medium'
  tag gid: 'V-217048'
  tag rid: 'SV-217048r639663_rule'
  tag stig_id: 'JUNI-RT-000430'
  tag gtitle: 'SRG-NET-000205-RTR-000011'
  tag fix_id: 'F-18275r297013_fix'
  tag 'documentable'
  tag legacy: ['SV-101091', 'V-90881']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
