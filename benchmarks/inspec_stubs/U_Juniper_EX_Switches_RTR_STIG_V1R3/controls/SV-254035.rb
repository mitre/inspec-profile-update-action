control 'SV-254035' do
  title 'The Juniper router must be configured to have Internet Control Message Protocol (ICMP) mask replies disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Mask Reply ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the device configuration to determine if controls have been defined to ensure the router does not send ICMP Mask Reply messages out to any external interfaces.

[edit policy-options]
prefix-list router-address-ipv4 {
    <external interface address>/32;
    <internal subnet>/<mask>;
}
[edit firewall family inet]
filter <name> {
    term 1 {
        from {
            source-prefix-list {
                router-address-ipv4; 
            }
            protocol icmp;
            icmp-type mask-reply;
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

[edit interfaces]
<external interface> {
    unit <number> {
        family inet {
            filter {
                output <filter name>;
            }
            address <IPv4 address>/<mask>;
        }
    }
}

Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If ICMP Mask Reply messages are enabled on any external interfaces, this is a finding.'
  desc 'fix', 'Disable ICMP mask replies on all external interfaces.

set policy-options prefix-list router-addresses-ipv4 <external interface address>/32
set policy-options prefix-list router-addresses-ipv4 <internal subnet>/<mask>

set firewall family inet filter <name> term 1 from source-prefix-list router-address-ipv4
set firewall family inet filter <name> term 1 from protocol icmp
set firewall family inet filter <name> term 1 from icmp-type mask-reply
set firewall family inet filter <name> term 1 then log
set firewall family inet filter <name> term 1 then syslog
set firewall family inet filter <name> term 1 then discard
<additional terms>
set firewall family inet filter <name> term default then log
set firewall family inet filter <name> term default then syslog
set firewall family inet filter <name> term default then discard

set interfaces <interface name> unit <number> family inet filter output <filter name>
set interfaces <interface name> unit <number> family inet address <IPv4 address>.<mask>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57487r844136_chk'
  tag severity: 'medium'
  tag gid: 'V-254035'
  tag rid: 'SV-254035r844138_rule'
  tag stig_id: 'JUEX-RT-000630'
  tag gtitle: 'SRG-NET-000362-RTR-000114'
  tag fix_id: 'F-57438r844137_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
