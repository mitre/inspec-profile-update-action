control 'SV-255992' do
  title 'The Arista BGP router must be configured to reject route advertisements from BGP peers that do not list their autonomous system (AS) number as the first AS in the AS_PATH attribute.'
  desc 'Verifying the path a route has traversed will ensure the IP core is not used as a transit network for unauthorized or possibly even internet traffic. All autonomous system boundary routers (ASBRs) must ensure updates received from eBGP peers list their AS number as the first AS in the AS_PATH attribute.'
  desc 'check', 'The feature below is enabled by default.

Verify the BGP configuration to deny the updates received from eBGP peer that do not have the proper AS in the AS_PATH_attribute. To verify the BGP config and that the feature is applied, execute the command "show run all | in first".

router bgp 65001
  bgp enforce-first-as 

If the router is not configured for "enforce-first-as", this is a finding.'
  desc 'fix', 'Configure all Arista ASBR routers to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.

LEAF-1A(config)#router  bgp 65001
LEAF-1A(config-router-bgp)#bgp enforce-first-as'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59668r882316_chk'
  tag severity: 'low'
  tag gid: 'V-255992'
  tag rid: 'SV-255992r882318_rule'
  tag stig_id: 'ARST-RT-000060'
  tag gtitle: 'SRG-NET-000018-RTR-000006'
  tag fix_id: 'F-59611r882317_fix'
  tag 'documentable'
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
