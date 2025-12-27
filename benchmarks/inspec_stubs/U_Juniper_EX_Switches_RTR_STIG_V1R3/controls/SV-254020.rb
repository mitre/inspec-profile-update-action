control 'SV-254020' do
  title 'The Juniper out-of-band management (OOBM) gateway router must be configured to block any traffic destined to itself that is not sourced from the OOBM network or the NOC.'
  desc 'If the gateway router is not a dedicated device for the OOBM network, several safeguards must be implemented for containment of management and production traffic boundaries. It is imperative that hosts from the managed network are not able to access the OOBM gateway router.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the firewall filter for the router receive path.

Verify that only traffic sourced from the OOBM network or the NOC is allowed to access the router.

[edit policy-options]
prefix-list OOBM-ipv4 {
    <IPv4 address>/<mask>;
}
prefix-list OOBM-ipv6 {
    <IPv6 address>/<prefix>;
}
prefix-list router-ipv4 {
    <IPv4 address>/<mask>;
}
prefix-list router-ipv6 {
    <IPv6 address>/<prefix>;
}

[edit firewall]
family inet {
    filter protect-re-ipv4 {
        term 1 {
            from {
                source-prefix-list OOBM-ipv4;
                destination-prefix-list router-ipv4;
            }
            then accept;
        }
        <additional terms for authorized traffic like OSPF or BGP>
        term default {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}
family inet6 {
    filter protect-re-ipv6 {
        term 1 {
            from {
                source-prefix-list OOBM-ipv6;
                destination-prefix-list router-ipv6;
            }
            then accept {
        }
        <additional terms for authorized traffic like OSPF or BGP>
        term default {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}

Verify the firewall filter is applied to the loopback interface.
[edit interfaces]
lo0 {
    unit 0 {
        family inet {
            filter {
                input protect-re-ipv4;   
            }                           
            address <IPv4 address/mask>;         
        }                               
        family inet6 {                  
            filter {                    
                input protect-re-ipv6;   
            }                           
            address <IPv6 address/prefix>;     
        }                               
    }                                   
}

Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If the router does not block any traffic destined to itself that is not sourced from the OOBM network or the NOC, this is a finding.

Note: If the platform does not support the receive path filter, verify that all non-OOBM interfaces have an ingress firewall filter to restrict access to that interface address or any of the router’s loopback addresses to only traffic sourced from the management network. An exception would be to allow packets destined to these interfaces used for troubleshooting, such as ping and traceroute.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Ensure that traffic from the managed network is not able to access the OOBM gateway router using either receive path or interface firewall filters.

set policy-options prefix-list OOBM-ipv4 <IPv4 address>/<mask>
set policy-options prefix-list OOBM-ipv6 <IPv6 address>/<prefix>

set firewall family inet filter protect-re-ipv4 term 1 from source-prefix-list OOBM-ipv4
set firewall family inet filter protect-re-ipv4 term 1 from destination-prefix-list router-ipv4
set firewall family inet filter protect-re-ipv4 term 1 then accept
<additional terms for authorized traffic like OSPF or BGP>
set firewall family inet filter protect-re-ipv4 term default then log
set firewall family inet filter protect-re-ipv4 term default then syslog
set firewall family inet filter protect-re-ipv4 term default then discard

set firewall family inet filter protect-re-ipv6 term 1 from source-prefix-list OOBM-ipv6
set firewall family inet filter protect-re-ipv6 term 1 from destination-prefix-list router-ipv6
set firewall family inet filter protect-re-ipv6 term 1 then accept
<additional terms for authorized traffic like OSPF or BGP>
set firewall family inet filter protect-re-ipv6 term default then log
set firewall family inet filter protect-re-ipv6 term default then syslog
set firewall family inet filter protect-re-ipv6 term default then discard

set interfaces lo0 unit 0 family inet filter input protect-re-ipv4
set interfaces lo0 unit 0 family inet address <IPv4 address>/<mask>
set interfaces lo0 unit 0 family inet6 filter input protect-re-ipv6
set interfaces lo0 unit 0 family inet6 address <IPv6 address>/<prefix>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57472r844091_chk'
  tag severity: 'medium'
  tag gid: 'V-254020'
  tag rid: 'SV-254020r844093_rule'
  tag stig_id: 'JUEX-RT-000480'
  tag gtitle: 'SRG-NET-000205-RTR-000011'
  tag fix_id: 'F-57423r844092_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
