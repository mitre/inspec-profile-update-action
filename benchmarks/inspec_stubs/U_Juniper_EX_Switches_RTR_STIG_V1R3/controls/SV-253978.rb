control 'SV-253978' do
  title 'The Juniper BGP router must be configured to reject route advertisements from BGP peers that do not list their autonomous system (AS) number as the first AS in the AS_PATH attribute.'
  desc 'Verifying the path a route has traversed will ensure the IP core is not used as a transit network for unauthorized or possibly even internet traffic. All autonomous system boundary routers (ASBRs) must ensure updates received from eBGP peers list their AS number as the first AS in the AS_PATH attribute.'
  desc 'check', 'Review the BGP router configuration to verify the router is configured to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.

Verify the configuration of "enforce-first-as" at either the BGP global or group level.
[edit protocols bgp]
group eBGP {
    enforce-first-as;
    neighbor <address>;
}
enforce-first-as;

If the router is not configured to reject updates from peers that do not list their AS number as the first AS in the AS_PATH attribute, this is a finding.'
  desc 'fix', 'Configure all ASBRs to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.

set protocols bgp group eBGP enforce-first-as
set protocols bgp group eBGP neighbor <address>
set protocols bgp enforce-first-as'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57430r843965_chk'
  tag severity: 'low'
  tag gid: 'V-253978'
  tag rid: 'SV-253978r843967_rule'
  tag stig_id: 'JUEX-RT-000060'
  tag gtitle: 'SRG-NET-000018-RTR-000006'
  tag fix_id: 'F-57381r843966_fix'
  tag 'documentable'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
