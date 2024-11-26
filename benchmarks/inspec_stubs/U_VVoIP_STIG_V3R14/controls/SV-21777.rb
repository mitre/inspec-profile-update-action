control 'SV-21777' do
  title 'A deny-by-default ACL for all VVoIP endpoint VLAN interfaces must be implemented on VVoIP non-core routing devices as defined in the VVoIP system ACL design.'
  desc 'Router ACLs are required to control access and the flow of traffic to and from VVoIP system devices and their VLANs as a protection mechanism. In general, the defined ACLs are designed in a deny-by-default manner such that only the protocols and traffic that needs to reach the device or devices in the VLAN receive the packets. The ACLs filter on VLAN, IP address and subnet, protocol type, and associated standard IP port for the protocol. In general, the ACLs mentioned are egress filters (referenced the router core) on the VLAN interfaces. Additionally, the routing devices should log and alarm on inappropriate traffic. An example of this is an HTTP request sourced from the data VLANs to the endpoint or media gateway VLANs. The primary purpose of ACL on all VVoIP VLAN interfaces is to block traffic to or from the data VLAN interfaces. Similar restrictions are placed on a dedicated VTC VLAN interface, however, VVoIP media and signaling is permitted in the event a VTC unit needs to communicate with the UC system.'
  desc 'check', 'Review site documentation, especially the VVoIP system ACL design, to confirm a deny-by-default ACL for all VVoIP endpoint VLAN interfaces is implemented on VVoIP non-core routing devices. Ensure a deny-by-default ACL is implemented on all VVoIP endpoint (hardware and software) VLAN interfaces on the VVoIP routing devices throughout the LAN that do not support the VVoIP system core equipment directly to control traffic as follows: 
- Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from other endpoint VLAN interfaces (VLAN/subnets) wherever they intersect. 
- Deny all other traffic. End the ACL with a “deny all” statement.

If a deny-by-default ACL for all VVoIP endpoint VLAN interfaces is not implemented on VVoIP non-core routing devices as defined in the VVoIP system ACL design, this is a finding.'
  desc 'fix', 'Implement and document a deny-by-default ACL for all VVoIP endpoint VLAN interfaces on VVoIP non-core routing devices as defined in the VVoIP system ACL design as follows: 
- Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from other endpoint VLAN interfaces (VLAN/subnets) wherever they intersect. 
- Deny all other traffic. End the ACL with a “deny all” statement.

All other EI traffic at this level in the network remains confined to the VLAN and is passed to the routing device that manages EI access to the VVoIP core equipment/infrastructure. The purpose of permitting media traffic to be routed between VVoIP EI VLANs at this level is to reduce the loading of the core routing device and LAN NEs in between. This also enhances QoS within the LAN itself.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23964r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19636'
  tag rid: 'SV-21777r3_rule'
  tag stig_id: 'VVoIP 5605'
  tag gtitle: 'VVoIP 5605'
  tag fix_id: 'F-20340r2_fix'
  tag 'documentable'
end
