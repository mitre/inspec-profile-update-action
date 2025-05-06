control 'SV-221028' do
  title 'The Cisco BGP switch must be configured to reject route advertisements from BGP peers that do not list their autonomous system (AS) number as the first AS in the AS_PATH attribute.'
  desc 'Verifying the path a route has traversed will ensure the IP core is not used as a transit network for unauthorized or possibly even internet traffic. All autonomous system boundary switches (ASBRs) must ensure updates received from eBGP peers list their AS number as the first AS in the AS_PATH attribute.'
  desc 'check', 'Review the switch configuration to verify the switch is configured to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.

By default, Cisco IOS enforces the first AS in the AS_PATH attribute for all route advertisements. Review the switch configuration to verify that the command no bgp enforce-first-as is not configured.

router bgp xx
 no synchronization
 no bgp enforce-first-as

If the switch is not configured to reject updates from peers that do not list their AS number as the first AS in the AS_PATH attribute, this is a finding.'
  desc 'fix', 'Configure the switch to deny updates received from eBGP peers that do not list their AS number as the first AS in the AS_PATH attribute.

SW1(config)#router bgp xx
SW1(config-switch)#bgp enforce-first-as'
  impact 0.3
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22743r408878_chk'
  tag severity: 'low'
  tag gid: 'V-221028'
  tag rid: 'SV-221028r622190_rule'
  tag stig_id: 'CISC-RT-000540'
  tag gtitle: 'SRG-NET-000018-RTR-000006'
  tag fix_id: 'F-22732r408879_fix'
  tag 'documentable'
  tag legacy: ['SV-110877', 'V-101773']
  tag cci: ['CCI-000032']
  tag nist: ['AC-4 (8) (a)']
end
