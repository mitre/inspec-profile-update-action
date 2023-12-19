control 'SV-21791' do
  title 'A LAN access switchport supports a VVoIP or VTC endpoint containing a PC port but is not configured with a default “data” VLAN to handle untagged PC port traffic and assign a secondary VVoIP or VTC VLAN to handle the tagged VVoIP or VTC traffic.'
  desc 'Many VVoIP and VTC endpoints provide a PC port on the device. Doing so permits a PC to share the same LAN drop as a VoIP phone or desktop VTC endpoint. The net effect is reduced installation and maintenance cost for the LAN infrastructure. Endpoints that provide a PC port have an embedded Ethernet switch which is required to support the separation of the PC data traffic from the VVoIP and VTC traffic. This is primarily accomplished by the embedded Ethernet switch in the endpoint supporting VLANs. In support of this, many VVoIP and VTC endpoints have the capability of adding a VLAN tag to their traffic using the 802.1Q format. Typically the PC port traffic is passed to the LAN unchanged whether the traffic is tagged or not, while adding the VVoIP VLAN tag for the locally defined VVoIP VLAN to its VVoIP traffic. 

NOTE: this is a limitation of the switchport access mode. It seems that configuring more than a default and tagged VLAN on a switchport requires the port to be set as a trunk, which is not permissible based on NET1416. This causes a limitation in the number of devices and applications that can be supported by a single switchport and LAN drop. For example, a single switchport will support a single VoIP phone (w/ an embedded switch and PC port) which tags its traffic and a connected PC that does not. Similarly, a single switchport will support a single VTC endpoint (w/ an embedded switch and PC port) which tags its traffic and a connected PC that does not. Similarly, a single switchport will support a single PC that supports a soft phone and tags its VoIP traffic while not tagging its data traffic (per the PCCC STIG). A single port will not support a VoIP phone and a VTC endpoint and a PC on a single drop unless the VTC endpoint also tags its VTC traffic with the VoIP VLAN. If a PC with a compliant soft phone is connected, it must also tag its traffic with the single VoIP VLAN tag. 

NOTE: Traffic to/from a VTC endpoint may use the same VLAN as the VVoIP phone system. Some exceptions may apply. NOTE: Do not use the default VLAN for the switch which is generally VLAN 1. This is used for LAN control traffic. No traffic or interface is permitted to be assigned to the switches’ default VLAN.'
  desc 'check', 'Inspect LAN access switchport configuration settings to confirm compliance with the following requirement:

In the event a LAN access switchport supports a VVoIP or VTC endpoint containing a PC port assign the switchport to a default “data” VLAN to handle untagged PC port traffic and assign a secondary VVoIP or VTC VLAN to handle the tagged VVoIP or VTC traffic.

NOTE: 802.1Q format is typically used for VLAN tagging in this application. While this is the standard method, this requirement is not intended to preclude other methods to affect the required behavior.

This is a finding in the event a LAN access switchport that supports a VVoIP or VTC endpoint containing a PC port is not configured with two VLANs, one that is a default “data” VLAN to handle untagged PC port traffic and a secondary VVoIP or VTC VLAN to handle the tagged VVoIP or VTC traffic.

NOTE: Do not use the default VLAN for the switch which is generally VLAN 1. This is used for LAN control traffic. No traffic or interface is permitted to be assigned to the switches’ default VLAN.'
  desc 'fix', 'In the event a LAN access switchport supports a VVoIP or VTC endpoint containing a PC port configure the switchport to assign a “default” “data” VLAN to handle untagged PC port traffic and assign a secondary VVoIP or VTC VLAN to handle the tagged VVoIP or VTC traffic.

NOTE: 802.1Q format is typically used for VLAN tagging in this application. While this is the standard method, this requirement is not intended to preclude other methods to affect the required behavior.

NOTE: Do not use the default VLAN for the switch which is generally VLAN 1. This is used for LAN control traffic. No traffic or interface is permitted to be assigned to the switches’ default VLAN.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23999r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19650'
  tag rid: 'SV-21791r2_rule'
  tag stig_id: 'VVoIP 5555'
  tag gtitle: 'Deficient LAN switch port config: 802.1Q VLAN Assn'
  tag fix_id: 'F-20354r1_fix'
  tag 'documentable'
end
