control 'SV-216782' do
  title 'The Cisco BGP router must be configured to reject route advertisements from BGP peers that do not list their autonomous system (AS) number as the first AS in the AS_PATH attribute.'
  desc 'Verifying the path a route has traversed will ensure the IP core is not used as a transit network for unauthorized or possibly even Internet traffic. All autonomous system boundary routers (ASBRs) must ensure updates received from eBGP peers list their AS number as the first AS in the AS_PATH attribute.'
  desc 'check', 'Review the router configuration to verify the router is configured to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.

By default Cisco IOS enforces the first AS in the AS_PATH attribute for all route advertisements. Review the router configuration to verify that the command bgp enforce-first-as disable is not configured as shown in the example below.

router bgp nn
 bgp enforce-first-as disable

If the router is not configured to reject updates from peers that do not list their AS number as the first AS in the AS_PATH attribute, this is a finding.'
  desc 'fix', 'Configure the router to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.

RP/0/0/CPU0:R2(config)#router bgp 2
RP/0/0/CPU0:R2(config-bgp)#no bgp enforce-first-as disable'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18014r288723_chk'
  tag severity: 'low'
  tag gid: 'V-216782'
  tag rid: 'SV-216782r531087_rule'
  tag stig_id: 'CISC-RT-000540'
  tag gtitle: 'SRG-NET-000018-RTR-000006'
  tag fix_id: 'F-18012r288724_fix'
  tag 'documentable'
  tag legacy: ['V-96771', 'SV-105909']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
