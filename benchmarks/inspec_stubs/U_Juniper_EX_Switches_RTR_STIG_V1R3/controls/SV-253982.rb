control 'SV-253982' do
  title 'The Juniper router configured for BGP must reject route advertisements from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.'
  desc 'Verifying the path a route has traversed will ensure that the local AS is not used as a transit network for unauthorized traffic. To ensure that the local AS does not carry any prefixes that do not belong to any customers, all PE routers must be configured to reject routes with an originating AS other than that belonging to the customer.'
  desc 'check', %q(This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to verify the router is configured to deny updates received from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.

Review the router configuration and verify that there is an as-path access-list statement defined. 

Each peer requires a regular expression (REGEX) defining the expected AS_PATH attribute. Each neighbor has an import policy applied to filter updates that do not match the expected path attribute. Assuming AS 65535 is an authorized neighbor's originating AS, verify an as-path REGEX is defined ('.* 65535') and a policy-statement configured to accept that REGEX.

[edit policy-options]
policy-statement bgp_originate_65535 {
    term 1 {
        from as-path orig_65535;
        then accept;
    }
    term 2 {
        then reject;
    }
}
as-path orig_65535 ".* 65535";
Note: The REGEX matches zero or more prepended AS in the AS_PATH beginning with the defined AS number (the originator is the right-most AS in the path). The AS_PATH attribute is a space-delimited list, so a space between the leading AS numbers (.*) and the originating AS (65535) is required.

Verify that the as-path access list is referenced by the filter-list inbound for the appropriate BGP neighbors.

[edit protocols bgp]
group eBGP {
    neighbor <address> {
        import bgp_originate_65535;
    }
}

If the router is not configured to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer, this is a finding.)
  desc 'fix', 'Configure the router to reject updates from CE routers with an originating AS in the AS_PATH attribute that does not belong to that customer.

set policy-options policy-statement bgp_originate_65535 term 1 from as-path orig_65535
set policy-options policy-statement bgp_originate_65535 term 1 then accept
set policy-options policy-statement bgp_originate_65535 term 2 then reject
set policy-options as-path orig_65535 ".* 65535"

set protocols bgp group eBGP neighbor <address> import bgp_originate_65535'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57434r843977_chk'
  tag severity: 'low'
  tag gid: 'V-253982'
  tag rid: 'SV-253982r843979_rule'
  tag stig_id: 'JUEX-RT-000100'
  tag gtitle: 'SRG-NET-000018-RTR-000010'
  tag fix_id: 'F-57385r843978_fix'
  tag 'documentable'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
