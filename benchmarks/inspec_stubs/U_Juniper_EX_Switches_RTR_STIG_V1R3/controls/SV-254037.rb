control 'SV-254037' do
  title 'The Juniper BGP router must be configured to use the prefix limit feature to protect against route table flooding and prefix deaggregation attacks.'
  desc "The effects of prefix deaggregation can degrade router performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured router, prefix deaggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.

In 1997, misconfigured routers in the Florida Internet Exchange network (AS7007) deaggregated every prefix in their routing table and started advertising the first /24 block of each of these prefixes as their own. Faced with this additional burden, the internal routers became overloaded and crashed repeatedly. This caused prefixes advertised by these routers to disappear from routing tables and reappear when the routers came back online. As the routers came back after crashing, they were flooded with the routing table information by their neighbors. The flood of information would again overwhelm the routers and cause them to crash. This process of route flapping served to destabilize not only the surrounding network but also the entire internet. Routers trying to reach those addresses would choose the smaller, more specific /24 blocks first. This caused backbone networks throughout North America and Europe to crash.

Maximum prefix limits on peer connections combined with aggressive prefix-size filtering of customers' reachability advertisements will effectively mitigate the deaggregation risk. BGP maximum prefix must be used on all eBGP routers to limit the number of prefixes that it should receive from a particular neighbor, whether customer or peering AS. Consider each neighbor and how many routes they should be advertising and set a threshold slightly higher than the number expected."
  desc 'check', 'Review the router configuration to verify that the number of received prefixes from each eBGP neighbor is controlled.

[edit protocols]
bgp {
    group <group name> {
        type external;
        local-as <local AS number>;
        neighbor <neighbor 1 address> {
            family inet {
                unicast {
                    prefix-limit {
                        maximum 10;
                        teardown;
                    }
                }
            }
            family inet6 {
                unicast {
                    prefix-limit {
                        maximum 10;
                        teardown;
                    }
                }
            }
            authentication-key "$8$aes256-gcm$hmac-sha2-256$100$cFQ99Gy83Og$SCMVXvnfna7/cZqH9fCECQ$bCVokm+es94xFJONmbKFNA$4561Uc/r"; ## SECRET-DATA
        }
        neighbor <neighbor 2 address> {
            family inet {
                unicast {
                    prefix-limit {
                        maximum 10;
                        teardown;
                    }
                }
            }
            family inet6 {
                unicast {
                    prefix-limit {
                        maximum 10;
                        teardown;
                    }
                }
            }
            ipsec-sa <SA name>;
        }
    }
}

If the router is not configured to control the number of prefixes received from each peer to protect against route table flooding and prefix deaggregation attacks, this is a finding.'
  desc 'fix', 'Configure all eBGP routers to use the prefix limit feature to protect against route table flooding and prefix deaggregation attacks.

set protocols bgp group <group name> type external
set protocols bgp group <group name> local-as <local AS number>
set protocols bgp group <group name> neighbor <neighbor 1 address> family inet unicast prefix-limit maximum 10
set protocols bgp group <group name> neighbor <neighbor 1 address> family inet unicast prefix-limit teardown
set protocols bgp group <group name> neighbor <neighbor 1 address> family inet6 unicast prefix-limit maximum 10
set protocols bgp group <group name> neighbor <neighbor 1 address> family inet6 unicast prefix-limit teardown
set protocols bgp group <group name> neighbor <neighbor 1 address> authentication-key <PSK value>
set protocols bgp group <group name> neighbor <neighbor 2 address> family inet unicast prefix-limit maximum 10
set protocols bgp group <group name> neighbor <neighbor 2 address> family inet unicast prefix-limit teardown
set protocols bgp group <group name> neighbor <neighbor 2 address> family inet6 unicast prefix-limit maximum 10
set protocols bgp group <group name> neighbor <neighbor 2 address> family inet6 unicast prefix-limit teardown
set protocols bgp group <group name> neighbor <neighbor 2 address> ipsec-sa <SA name>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57489r844142_chk'
  tag severity: 'medium'
  tag gid: 'V-254037'
  tag rid: 'SV-254037r844144_rule'
  tag stig_id: 'JUEX-RT-000650'
  tag gtitle: 'SRG-NET-000362-RTR-000117'
  tag fix_id: 'F-57440r844143_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
