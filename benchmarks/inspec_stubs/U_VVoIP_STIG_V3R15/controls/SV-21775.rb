control 'SV-21775' do
  title 'VLANs established for the VVoIP system are NOT pruned from trunks and/or interfaces that are not required to carry the VVoIP traffic'
  desc 'While VLANs facilitate access and traffic control for the VVoIP system components and enhanced QoS, they should only be implemented on the network elements that are needed to carry the traffic from the attached devices. LAN switches will typically learn the VLANs configured on an adjacent switch and configure it locally. As such a VLAN configured on one switch can be learned and configured on the entire LAN in a very short period of time. Too many learned VLANs and a NE can crash. Additionally, a VLAN that appears on NEs where it is not required to carry traffic, places the VLAN at risk of compromise by presenting many more points at which the VLAN might be accessed. Therefore the VLANs must be pruned from trunks and interfaces where the VLAN does not need to send traffic. A VLAN that supports a number of local VVoIP endpoints only needs to traverse the NEs in two paths to the core routing devices at the VVoIP core equipment, Any specific endpoint VLAN does not need to appear on every switch in the LAN unless it serves endpoints everywhere on the LAN. Likewise the VVoIP core equipment VLANs do not need to extend past the VVoIP core routing devices (routers or layer 3 switches. The endpoint VLANs come to the core, the core VLANs do not extend to the endpoints. As such all VLANs must be pruned from any trunk where its traffic does not need to go.'
  desc 'check', 'Inspect the configurations of the LAN devices supporting the VVoIP system on which the required VLANs are configured to determine compliance with the following requirement:

Ensure VLANs established for the VVoIP system are pruned from trunks and/or interfaces that are not required to carry the traffic as follows:
> VVoIP core equipment VLANs will not extend past the core routing devices that support the core equipment. These VLANs should not appear on distribution or access layer NEs in the LAN.
> VVoIP endpoint VLANs established on access layer switches shall only appear on a primary uplink and a backup in addition to the access ports that are assigned to the local VVoIP VLAN. 
> VVoIP endpoint VLANs established on distribution layer switches shall only appear on a primary uplink and a backup that leads toward a routing device. If the distribution layer switch is a routing device, there may be other endpoint VLANs present and available for routing or a local VLAN may traverse a horizontal link if available to another distribution layer NE for routing. Typically however this routing should occur on the core routing devices rather than traversing horizontal links to be routed.'
  desc 'fix', 'Ensure VLANs established for the VVoIP system are pruned from trunks and/or interfaces that are not required to carry the traffic as follows:
> VVoIP core equipment VLANs will not extend past the core routing devices that support the core equipment. These VLANs should not appear on distribution or access layer NEs in the LAN.
> VVoIP endpoint VLANs established on access layer switches shall only appear on a primary uplink and a backup in addition to the access ports that are assigned to the local VVoIP VLAN. 
> VVoIP endpoint VLANs established on distribution layer switches shall only appear on a primary uplink and a backup that leads toward a routing device. If the distribution layer switch is a routing device, there may be other endpoint VLANs present and available for routing or a local VLAN may traverse a horizontal link if available to another distribution layer NE for routing. Typically however this routing should occur on the core routing devices rather than traversing horizontal links to be routed.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23960r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19634'
  tag rid: 'SV-21775r2_rule'
  tag stig_id: 'VVoIP 5530'
  tag gtitle: "Deficient imp'n: VVoIP VLAN pruning within the LAN"
  tag fix_id: 'F-20338r1_fix'
  tag 'documentable'
end
