control 'SV-254010' do
  title 'The Juniper router must be configured to restrict traffic destined to itself.'
  desc 'The routing engine (RE) handles traffic destined to the router—the key component used to build forwarding paths and is also instrumental with all network management functions. Hence, any disruption or DoS attack to the RE can result in mission critical network outages.'
  desc 'check', 'Review the firewall filter for the router receive path and verify that it will only process specific management plane and control plane traffic from specific sources. For example:
[edit policy-options]
auth_mgt_networks-ipv4 {
    <IPv4 subnet / mask>;
}
auth_mgt_networks-ipv6 {
    <IPv6 subnet / prefix>;
}
device_mgt_address-ipv4 {
    <IPv4 address>/32;
}
device_mgt_address-ipv6 {
    <IPv6 address>/128;
}
[edit firewall]
family inet {
    filter protect_re-ipv4 {
        term 1 {
            from {
                source-prefix-list auth_mgt_networks-ipv4;
                destination-prefix-list device_mgt_address-ipv4;
                <additional match criteria>;
            }
        }
        <additional permit terms>
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
    filter protect_re-ipv6 {
        term 1 {
            from {
                source-prefix-list auth_mgt_networks-ipv6;
                destination-prefix-list device_mgt_address-ipv6;
                <additional match criteria>;
            }
        }
        <additional permit terms>
        term default {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}

Note: Additional match criteria includes protocol (next-header for IPv6), source and destination ports, ICMP type and code, etc. When applied to the loopback interface, the filter affects identified traffic regardless of ingress interface. Ensure the filter addresses all traffic destined to the RE like routing protocols, ICMP messages, SSH and SCP traffic, SNMP, etc.

Verify filters are applied to loopback, all L3 interfaces, or both. For example:
[edit interfaces]
lo0 {
    unit 0 {
        family inet {
            filter {
                input protect_re-ipv4;
            }
            address <IPv4 address>/32;
        }
        family inet6 {
            filter {
                input protect_re-ipv6;
            }
            address <IPv6 address>/32;
        }
    }
}
Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If the router is not configured with a receive-path filter to restrict traffic destined to itself, this is a finding.

Note: If the platform does not support the receive path filter, verify that all layer 3 interfaces have an ingress firewall filter to control what packets are allowed to be destined to the router for processing.'
  desc 'fix', 'Configure all routers with receive path filters to restrict traffic destined to the router.

Example prefix lists for management networks and the device management address(es):
set prefix-list auth_mgt_networks-ipv4 <IPv4 subnet / mask>
set prefix-list auth_mgt_networks-ipv6 <IPv6 subnet / mask>
set prefix-list device_mgt_address-ipv4 <IPv4 address>/32
set prefix-list device_mgt_address-ipv6 <IPv6 address>/128

Example firewall filters:
set firewall family inet filter protect_re-ipv4 term 1 from source-prefix-list auth_mgt_networks-ipv4
set firewall family inet filter protect_re-ipv4 term 1 from destination-prefix-list device_mgt_address-ipv4
set firewall family inet filter protect_re-ipv4 term 1 from <additional match criteria>
set firewall family inet filter protect_re-ipv4 term 1 then accept
set firewall family inet filter protect_re-ipv4 term <additional permit terms>
set firewall family inet filter protect_re-ipv4 term default then log
set firewall family inet filter protect_re-ipv4 term default then syslog
set firewall family inet filter protect_re-ipv4 term default then discard

set firewall family inet6 filter protect_re-ipv6 term 1 from source-prefix-list auth_mgt_networks-ipv6
set firewall family inet6 filter protect_re-ipv6 term 1 from destination-prefix-list device_mgt_address-ipv6
set firewall family inet6 filter protect_re-ipv6 term 1 from <additional match criteria>
set firewall family inet6 filter protect_re-ipv6 term 1 then accept
set firewall family inet6 filter protect_re-ipv6 term <additional permit terms>
set firewall family inet6 filter protect_re-ipv6 term default then log
set firewall family inet filter protect_re-ipv6 term default then syslog
set firewall family inet filter protect_re-ipv6 term default then discard

Example application on loopback:
set interfaces lo0 unit 0 family inet filter input protect_re-ipv4
set interfaces lo0 unit 0 family inet address <IPv4 address>/32
set interfaces lo0 unit 0 family inet6 filter input protect_re-ipv6
set interfaces lo0 unit 0 family inet6 address <IPv6 address>/128'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57462r844061_chk'
  tag severity: 'high'
  tag gid: 'V-254010'
  tag rid: 'SV-254010r844063_rule'
  tag stig_id: 'JUEX-RT-000380'
  tag gtitle: 'SRG-NET-000205-RTR-000001'
  tag fix_id: 'F-57413r844062_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
