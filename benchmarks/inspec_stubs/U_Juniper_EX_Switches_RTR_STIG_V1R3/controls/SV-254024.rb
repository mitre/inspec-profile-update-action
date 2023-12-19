control 'SV-254024' do
  title 'The Juniper PE router must be configured to ignore or block all packets with any IP options.'
  desc 'Packets with IP options are not fast switched and, therefore, must be punted to the route engine (RE). Hackers who initiate denial-of-service (DoS) attacks on routers commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the router. The end result is a reduction in the effects of the DoS attack on the router and on downstream routers.'
  desc 'check', 'Review the router configuration to determine if it will block all packets with IP options.

[edit firewall family inet]
filter <name> {
    term 1 {
        from {
            ip-options any;
        }
        then {
            log;
            syslog;
            discard;
        }
    }
    <additional accept terms>
    term default {
        then {
            log;
            syslog;
            discard;
        }
    }
}
[edit interfaces]
<interface name> {
    unit <number> {
        family inet {
            filter input <filter name>;
            address <IPv4 address>/<mask>;
        }
    }
}

Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If the router is not configured to drop all packets with IP options, this is a finding.'
  desc 'fix', 'Configure the router to drop all packets with IP options.

set firewall family inet filter <filter name> term 1 from ip-options any
set firewall family inet filter <filter name> term 1 then log
set firewall family inet filter <filter name> term 1 then syslog
set firewall family inet filter <filter name> term 1 then discard
<additional accept terms>
set firewall family inet filter default term 1 then log
set firewall family inet filter default term 1 then syslog
set firewall family inet filter default term 1 then discard

set interfaces <interface name> unit <number> family inet filter input <filter name>
set interfaces <interface name> unit <number> family inet address <IPv4 address>/<mask>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57476r844103_chk'
  tag severity: 'medium'
  tag gid: 'V-254024'
  tag rid: 'SV-254024r844105_rule'
  tag stig_id: 'JUEX-RT-000520'
  tag gtitle: 'SRG-NET-000205-RTR-000016'
  tag fix_id: 'F-57427r844104_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
