control 'SV-253984' do
  title 'The Juniper router must be configured to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.'
  desc 'Information flow control regulates authorized information to travel within a network and between interconnected networks. Controlling the flow of network traffic is critical so it does not introduce any unacceptable risk to the network infrastructure or data. An example of a flow control restriction is blocking outside traffic claiming to be from within the organization. For most routers, internal information flow control is a product of system design.'
  desc 'check', %q(Verify each router enforces approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.

Junos enforces information flow via stateless firewall filters and unicast Reverse Path Forwarding (uRPF). uRPF performs a forwarding table lookup to validate the incoming packet's source address is appropriate for the arriving interface. Verify uRPF is enabled on applicable interfaces. The example shows uRPF and the stateless firewall filter applied. Verify the interface and assigned addresses are appropriate for the target environment.

[edit interfaces]
<interface name> {
    unit <logical unit number> {
        family inet {
            rpf-check;
           filter {
              input deny-prod-to-mgt;
           }
        }
        family inet6 {
           rpf-check;
           filter {
              input deny-prod-to-mgt-v6;
           }
        }
    }
}
Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. 

[edit firewall]
family inet {
    filter deny-prod-to-mgt {
        term 1 {
            from {
                source-address {
                    <production IPv4 subnet/mask>;
                }
                destination-address {
                    <MGT IPv4 subnet/mask>;
                }
            }
            then {
                log;
                syslog;
                discard;
            }
        }
        term 2 {
            from {
                source-address {
                    <production IPv4 subnet/mask>;
                }
            }
            then accept;
        }
    }
}
family inet6 {
    filter deny-prod-to-mgt-v6 {
        term 1 {                        
            from {
                source-address {
                     <production IPv6 subnet/prefix>;
                }
                destination-address {
                    <MGT IPv6 subnet/prefix>;
                }
            }
            then {
                log;
                syslog;
                discard;
            }
        }
        term 2 {
            from {
                source-address {
                    <production IPv6 subnet/prefix>;
                }
            }
            then accept;
        }
    }
}

If the router does not enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy, this is a finding.)
  desc 'fix', 'Configure the router to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.

set interfaces <interface name> unit <logical unit> family inet rpf-check
set interfaces <interface name> unit <logical unit> family inet filter input deny-prod-to-mgt
set interfaces <interface name> unit <logical unit> family inet6 rpf-check
set interfaces <interface name> unit <logical unit> family inet6 filter input deny-prod-to-mgt-v6

set firewall family inet filter deny-prod-to-mgt term 1 from source-address <production IPv4 subnet/mask>
set firewall family inet filter deny-prod-to-mgt term 1 from destination-address <MGT IPv4 subnet/mask>
set firewall family inet filter deny-prod-to-mgt term 1 then log
set firewall family inet filter deny-prod-to-mgt term 1 then syslog
set firewall family inet filter deny-prod-to-mgt term 1 then discard
set firewall family inet filter deny-prod-to-mgt term 2 from source-address <production IPv4 subnet/mask>
set firewall family inet filter deny-prod-to-mgt term 2 then accept

set firewall family inet6 filter deny-prod-to-mgt-v6 term 1 from source-address <production IPv6 subnet/prefix>
set firewall family inet6 filter deny-prod-to-mgt-v6 term 1 from destination-address <MGT IPv6 subnet/prefix>
set firewall family inet6 filter deny-prod-to-mgt-v6 term 1 then log
set firewall family inet6 filter deny-prod-to-mgt-v6 term 1 then syslog
set firewall family inet6 filter deny-prod-to-mgt-v6 term 1 then discard
set firewall family inet6 filter deny-prod-to-mgt-v6 term 2 from source-address <production IPv6 subnet/prefix>
set firewall family inet6 filter deny-prod-to-mgt-v6 term 2 then accept'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57436r843983_chk'
  tag severity: 'medium'
  tag gid: 'V-253984'
  tag rid: 'SV-253984r843985_rule'
  tag stig_id: 'JUEX-RT-000120'
  tag gtitle: 'SRG-NET-000019-RTR-000002'
  tag fix_id: 'F-57387r843984_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
