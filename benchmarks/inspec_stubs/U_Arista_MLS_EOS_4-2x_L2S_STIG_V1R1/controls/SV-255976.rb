control 'SV-255976' do
  title 'The Arista MLS layer 2 switch must have IGMP or MLD Snooping configured on all VLANs.'
  desc 'IGMP and MLD snooping provides a way to constrain multicast traffic at Layer 2. By monitoring the IGMP or MLD membership reports sent by hosts within a VLAN, the snooping application can set up Layer 2 multicast forwarding tables to deliver specific multicast traffic only to interfaces connected to hosts interested in receiving the traffic, thereby significantly reducing the volume of multicast traffic that would otherwise flood the VLAN.'
  desc 'check', 'Review the Arista MLS switch configuration to verify that IGMP or MLD snooping has been configured.

Determine which snooping feature is used.

For IGMP:
Verify the PIM that also enables IGMP on an Arista MLS switch VLAN interface by using the "sh run interface vlan8" command:

switch(config)#sh run int vlan8
interface VLAN8
   ip igmp
   pim ipv4 sparse-mode
switch(config)#exit

For MLD:
Verify the Arista MLS switch is configured for MLD snooping on an interface for version 1 and 2. Version 2 is the default MLD version.

switch#sh run | section mld
 mld snooping
   vlan 200

If the Arista switch is not configured to implement IGMP or MLD snooping for each VLAN, this is a finding.'
  desc 'fix', 'Configure the Arista MLS switch for IGMP snooping for IPv4 and IPv6 multicast traffic for each VLAN.

Configure the Arista MLS switch for IP PIM, which also enables IGMP on an Arista MLS switch VLAN or interface, by using the following command:

switch(config)#int vlan8
   ip igmp
   pim ipv4 sparse-mode
   pim ipv6 sparse-mode
switch(config)#exit
!

Arista MLS switch alternative configuration for MLD snooping on an interface for version 1 and 2. Version 2 is the default MLD version.

switch(config)# mld snooping
switch(config-mld-snooping)# vlan 200
!'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x L2S'
  tag check_id: 'C-59652r882268_chk'
  tag severity: 'low'
  tag gid: 'V-255976'
  tag rid: 'SV-255976r882270_rule'
  tag stig_id: 'ARST-L2-000130'
  tag gtitle: 'SRG-NET-000512-L2S-000002'
  tag fix_id: 'F-59595r882269_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
