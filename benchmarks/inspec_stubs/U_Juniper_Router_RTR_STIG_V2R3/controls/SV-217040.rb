control 'SV-217040' do
  title 'The Juniper perimeter router must be configured to block all packets with any IP options.'
  desc 'Packets with IP options are not fast switched and henceforth must be punted to the router processor. Hackers who initiate denial-of-service (DoS) attacks on routers commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the router. The end result is a reduction in the effects of the DoS attack on the router and on downstream routers.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the router configuration to determine if it will block all packets with IP options.

firewall {
    family inet {
        filter INBOUND_FILTER {
            term DROP_IPOPTIONS {
                from {
                    ip-options any;
                }
                then {
                    syslog;
                    discard;
                }
            }
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
            term ALLOW_ABC {
            …
            …
            …
            term DENY_ALL_OTHER {
                then {
                    log;
                    syslog;
                    reject;
                }
            }
        }

If the router is not configured to drop all packets with IP options, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the router to drop all packets with IP options.

[edit firewall family inet filter INBOUND_FILTER]
set term DROP_IPOPTIONS from ip-options any
set term DROP_IPOPTIONS then discard
insert term DROP_IPOPTIONS before  term BLOCK_BOGONS'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18269r296988_chk'
  tag severity: 'medium'
  tag gid: 'V-217040'
  tag rid: 'SV-217040r604135_rule'
  tag stig_id: 'JUNI-RT-000350'
  tag gtitle: 'SRG-NET-000205-RTR-000015'
  tag fix_id: 'F-18267r296989_fix'
  tag 'documentable'
  tag legacy: ['SV-101075', 'V-90865']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
