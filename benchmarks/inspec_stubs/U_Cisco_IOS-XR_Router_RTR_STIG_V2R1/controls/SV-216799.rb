control 'SV-216799' do
  title 'The Cisco PE router must be configured to implement Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) snooping for each Virtual Private LAN Services (VPLS) bridge domain.'
  desc 'IGMP snooping provides a way to constrain multicast traffic at Layer 2. By monitoring the IGMP membership reports sent by hosts within the bridge domain, the snooping application can set up Layer 2 multicast forwarding tables to deliver traffic only to ports with at least one interested member within the VPLS bridge, thereby significantly reducing the volume of multicast traffic that would otherwise flood an entire VPLS bridge domain. The IGMP snooping operation applies to both access circuits and pseudowires within a VPLS bridge domain.'
  desc 'check', 'Review the router configuration to verify that IGMP or MLD snooping has been configured for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain. 

l2vpn
 bridge group L2GROUP
  bridge-domain L2_BRIDGE_COI1
   interface GigabitEthernet0/0/0/2
    igmp snooping profile default

If the router is not configured to implement IGMP or MLD snooping for each VPLS bridge domain, this is a finding.'
  desc 'fix', 'Configure IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain.

RP/0/0/CPU0:R3(config)#l2vpn
RP/0/0/CPU0:R3(config-l2vpn)#bridge group L2GROUP
RP/0/0/CPU0:R3(config-l2vpn-bg)# bridge-domain L2_BRIDGE_COI1
RP/0/0/CPU0:R3(config-l2vpn-bg-bd)#interface GigabitEthernet0/0/0/2
RP/0/0/CPU0:R3(config-l2vpn-bg-bd-ac)#igmp snooping profile default
RP/0/0/CPU0:R3(config-l2vpn-bg-bd-ac)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18031r288774_chk'
  tag severity: 'low'
  tag gid: 'V-216799'
  tag rid: 'SV-216799r531087_rule'
  tag stig_id: 'CISC-RT-000710'
  tag gtitle: 'SRG-NET-000362-RTR-000119'
  tag fix_id: 'F-18029r288775_fix'
  tag 'documentable'
  tag legacy: ['SV-105943', 'V-96805']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
