control 'SV-254038' do
  title 'The Juniper BGP router must be configured to limit the prefix size on any inbound route advertisement to /24 or the least significant prefixes issued to the customer.'
  desc 'The effects of prefix deaggregation can degrade router performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured router, prefix deaggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.'
  desc 'check', %q(This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to verify that there is a filter to reject inbound route advertisements that are greater than /24, or the least significant prefixes issued to the customer, whichever is larger. Verify each BGP neighbor implements an import policy. BGP import policies are supported in three locations: Global (at [edit protocols bgp]), group (at [edit protocols bgp group <name>]), and for each neighbor (at [edit protocols bgp group <name> neighbor <neighbor address>]) with the most specific import statement being applied. Multiple policy statements may be necessary to address each customer's requirements.

[edit policy-options]
policy-statement reject-long-prefixes {
    term 1 {
        from {
            route-filter 0.0.0.0/0 prefix-length-range /25-/32;
        }
        then reject;
    }
    <additional terms>
}
[edit protocols]
bgp {
    group <group name> {
        type external;
        import <policy statement name>; << Applied instead of global BGP policy unless a more specific neighbor import filter exists. Excludes all terms in the global filter.
        local-as <local AS number>;
        neighbor <neighbor 1 address> {
            import <policy statement name>; << Most specific import filter. If configured, only this filter applies to this neighbor (all other terms in all other filters ignored).
            authentication-key "$8$aes256-gcm$hmac-sha2-256$100$cFQ99Gy83Og$SCMVXvnfna7/cZqH9fCECQ$bCVokm+es94xFJONmbKFNA$4561Uc/r"; ## SECRET-DATA
        }
        neighbor <neighbor 2 address> {
            import <policy statement name>; << Most specific import filter. If configured, only this filter applies to this neighbor (all other terms in all other filters ignored).
            ipsec-sa <SA name>;
        }
    }
    import <policy statement name>; << Least specific import filter.
}

If the router is not configured to limit the prefix size on any inbound route advertisement to /24 or the least significant prefixes issued to the customer, this is a finding.)
  desc 'fix', 'Configure all eBGP routers to use the prefix limit feature to protect against route table flooding and prefix deaggregation attacks.

set policy-options policy-statement <statement name> term 1 from route-filter 0.0.0.0/0 prefix-length-range /25-/32
set policy-options policy-statement <statement name> term 1 then reject

set protocols bgp group <group name> type external
set protocols bgp group <group name> import <statement name>
set protocols bgp group <group name> local-as <local AS number>
set protocols bgp group <group name> neighbor <neighbor 1 address> import <statement name>
set protocols bgp group <group name> neighbor <neighbor 1 address> authentication-key <PSK value>
set protocols bgp group <group name> neighbor <neighbor 2 address> import <statement name>
set protocols bgp group <group name> neighbor <neighbor 2 address> ipsec-sa <SA name>
set protocols bgp import <statement name>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57490r844145_chk'
  tag severity: 'low'
  tag gid: 'V-254038'
  tag rid: 'SV-254038r844147_rule'
  tag stig_id: 'JUEX-RT-000660'
  tag gtitle: 'SRG-NET-000362-RTR-000118'
  tag fix_id: 'F-57441r844146_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
