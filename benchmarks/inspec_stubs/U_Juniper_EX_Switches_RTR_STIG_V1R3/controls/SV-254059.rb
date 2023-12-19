control 'SV-254059' do
  title 'The Juniper perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop or Destination Option extension header with an undefined option type.'
  desc 'The optional and extensible natures of the IPv6 extension headers require higher scrutiny since many implementations do not always drop packets with headers that it cannot recognize, and hence could cause a denial-of-service on the target device. In addition, the type, length, value (TLV) formatting provides the ability for headers to be very large.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration and determine if filters are bound to the applicable interfaces to drop all inbound IPv6 packets containing an undefined option type value regardless of whether they appear in a Hop-by-Hop or Destination Option header. Undefined values are 0x02, 0x03, 0x06, 0x9 – 0xE, 0x10 – 0x22, 0x24, 0x25, 0x27 – 0x2F, and 0x31 – 0xFF.

Verify the router drops all hop-by-hop and destination-options extension headers.
[edit firewall family inet6]
filter <name> {
    term 1 {
        from {
            next-header [ hop-by-hop dstopts ];
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

Note: Juniper routers do not support configuring option types for either the Hop-by-Hop or Destination Options extension headers. Therefore, all packets with the Hop-by-Hop or Destination Options extension header are dropped.

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

If the router is not configured to drop IPv6 packets containing a Hop-by-Hop or Destination Option extension header, this is a finding.'
  desc 'fix', 'Configure the router to drop all inbound IPv6 packets containing an undefined option type value regardless of whether or not they appear in a Hop-by-Hop or Destination Option header.

set firewall family inet6 filter <name> term 1 from next-header hop-by-hop
set firewall family inet6 filter <name> term 1 from next-header dstopts
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
  tag check_id: 'C-57511r844208_chk'
  tag severity: 'medium'
  tag gid: 'V-254059'
  tag rid: 'SV-254059r844210_rule'
  tag stig_id: 'JUEX-RT-000870'
  tag gtitle: 'SRG-NET-000364-RTR-000206'
  tag fix_id: 'F-57462r844209_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
