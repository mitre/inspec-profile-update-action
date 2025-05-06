control 'SV-221124' do
  title 'The Cisco PE switch must be configured to implement Internet Group Management Protocol (IGMP) or Multicast Listener Discovery (MLD) snooping for each Virtual Private LAN Services (VPLS) bridge domain.'
  desc 'IGMP snooping provides a way to constrain multicast traffic at Layer 2. By monitoring the IGMP membership reports sent by hosts within the bridge domain, the snooping application can set up Layer 2 multicast forwarding tables to deliver traffic only to ports with at least one interested member within the VPLS bridge, thereby significantly reducing the volume of multicast traffic that would otherwise flood an entire VPLS bridge domain. The IGMP snooping operation applies to both access circuits and pseudowires within a VPLS bridge domain.'
  desc 'check', 'Review the switch configuration to verify that IGMP or MLD snooping has been configured for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain. The example below are the steps to verify that IGMP snooping is enabled for a VPLS bridge domain.

Step 1: Verify that IGMP snooping is enabled globally. By default, IGMP snooping is enabled globally; hence, the following command should not be in the switch configuration: no ip igmp snooping

Step 2: If IGMP snooping is enabled globally, it will also be enabled by default for each VPLS bridge domain. Hence, the command “no ip igmp snooping” should not be configured for any VPLS bridge domain as shown in the example below:

bridge-domain 100 
 no ip igmp snooping

If the switch is not configured to implement IGMP or MLD snooping for each VPLS bridge domain, this is a finding.'
  desc 'fix', 'Configure IGMP or MLD snooping for IPv4 and IPv6 multicast traffic respectively for each VPLS bridge domain.

SW1(config)# bridge-domain 100
SW1(config-bdomain)# ip igmp snooping 
SW1(config-bdomain)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22839r409861_chk'
  tag severity: 'low'
  tag gid: 'V-221124'
  tag rid: 'SV-221124r622190_rule'
  tag stig_id: 'CISC-RT-000710'
  tag gtitle: 'SRG-NET-000362-RTR-000119'
  tag fix_id: 'F-22828r409862_fix'
  tag 'documentable'
  tag legacy: ['SV-111067', 'V-101963']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
