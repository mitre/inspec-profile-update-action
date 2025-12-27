control 'SV-216692' do
  title 'The Cisco BGP router must be configured to reject route advertisements from BGP peers that do not list their autonomous system (AS) number as the first AS in the AS_PATH attribute.'
  desc 'Verifying the path a route has traversed will ensure the IP core is not used as a transit network for unauthorized or possibly even internet traffic. All autonomous system boundary routers (ASBRs) must ensure updates received from eBGP peers list their AS number as the first AS in the AS_PATH attribute.'
  desc 'check', 'Review the router configuration to verify the router is configured to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.

By default, Cisco IOS enforces the first AS in the AS_PATH attribute for all route advertisements. Review the router configuration to verify that the command no bgp enforce-first-as is not configured.

router bgp xx
 no synchronization
 no bgp enforce-first-as

If the router is not configured to reject updates from peers that do not list their AS number as the first AS in the AS_PATH attribute, this is a finding.'
  desc 'fix', 'Configure the router to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.

R1(config)#router bgp xx
R1(config-router)#bgp enforce-first-as'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17925r288021_chk'
  tag severity: 'low'
  tag gid: 'V-216692'
  tag rid: 'SV-216692r531086_rule'
  tag stig_id: 'CISC-RT-000540'
  tag gtitle: 'SRG-NET-000018-RTR-000006'
  tag fix_id: 'F-17923r288022_fix'
  tag 'documentable'
  tag legacy: ['V-96957', 'SV-106095']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
