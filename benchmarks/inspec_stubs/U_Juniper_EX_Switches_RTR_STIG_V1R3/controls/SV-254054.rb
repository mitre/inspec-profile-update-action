control 'SV-254054' do
  title 'The Juniper perimeter router must be configured drop IPv6 packets with a Routing Header type 0, 1, or 3255.'
  desc 'The routing header can be used maliciously to send a packet through a path where less robust security is in place, rather than through the presumably preferred path of routing protocols. Use of the routing extension header has few legitimate uses other than as implemented by Mobile IPv6. 

The Type 0 Routing Header (RFC 5095) is dangerous because it allows attackers to spoof source addresses and obtain traffic in response, rather than the real owner of the address. Secondly, a packet with an allowed destination address could be sent through a Firewall using the Routing Header functionality, only to bounce to a different node once inside. The Type 1 Routing Header is defined by a specification called "Nimrod Routing", a discontinued project funded by DARPA. Assuming that most implementations will not recognize the Type 1 Routing Header, it must be dropped. The Type 3–255 Routing Header values in the routing type field are currently undefined and should be dropped inbound and outbound.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to determine if it is configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3–255.

[edit firewall family inet6]
filter <name> {
    term 1 {
        from {
            next-header routing;
        }
        then {
            log;
            syslog;
            discard;
        }
    }
    <additional terms>
    term default {
        then {
            log;
            syslog;
            discard;
        }
    }
}

Note: Juniper routers do not support configuring option types for Routing extension headers. Therefore, all packets with the Routing extension header are dropped.

Verify the filter is applied to applicable interfaces.
[edit interfaces]
<interface name> {
    unit <number> {
        family inet6 {
            filter {
                input <filter name>;
            }
            address <IPv6 address>.<prefix>;
        }
    }
}
Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If the router is not configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3–255, this is a finding.'
  desc 'fix', 'Configure the router to drop IPv6 packets with Routing Header of type 0, 1, or 3–255.

set firewall family inet6 filter <name> term 1 from next-header routing
set firewall family inet6 filter <name> term 1 then log
set firewall family inet6 filter <name> term 1 then syslog
set firewall family inet6 filter <name> term 1 then discard
<additional terms>
set firewall family inet6 filter <name> term default then log
set firewall family inet6 filter <name> term default then syslog
set firewall family inet6 filter <name> term default then discard

set interfaces <interface name> unit <number> family inet6 filter input <filter name>
set interfaces <interface name> unit <number> family inet6 address <IPv6 address>.<prefix>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57506r844193_chk'
  tag severity: 'medium'
  tag gid: 'V-254054'
  tag rid: 'SV-254054r844195_rule'
  tag stig_id: 'JUEX-RT-000820'
  tag gtitle: 'SRG-NET-000364-RTR-000201'
  tag fix_id: 'F-57457r844194_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
