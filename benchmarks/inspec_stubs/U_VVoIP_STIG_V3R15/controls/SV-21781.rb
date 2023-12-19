control 'SV-21781' do
  title 'A deny-by-default ACL for session border VLAN interfaces must be implemented on VVoIP core routing devices as defined in the VVoIP system ACL design.'
  desc 'Router ACLs are required to control access and the flow of traffic to and from VVoIP system devices and their VLANs as a protection mechanism. In general the defined ACLs are designed in a deny-by-default manner such that only the protocols and traffic that needs to reach the device or devices in the VLAN receive the packets. The ACLs filter on VLAN, IP address and subnet, protocol type, and associated standard IP port for the protocol. In general, the ACLs mentioned are egress filters (referenced the router core) on the VLAN interfaces. Additionally, the routing devices should log and alarm on inappropriate traffic. An example of this is an HTTP request sourced from the data VLANs to the endpoint or media gateway VLANs. The primary purpose of ACL on all VVoIP VLAN interfaces is to block traffic to or from the data VLAN interfaces. Similar restrictions are placed on a dedicated VTC VLAN interface, however, VVoIP media and signaling is permitted in the event a VTC unit needs to communicate with the UC system .'
  desc 'check', 'Review site documentation, especially the VVoIP system ACL design, to confirm a deny-by-default ACL for session border VLAN interfaces is implemented on VVoIP core routing devices. Ensure a deny-by-default ACL is implemented on the VVoIP session border controller VLAN or firewall VLAN interfaces on the VVoIP routing devices supporting the VVoIP system core equipment to control traffic as follows: 
- Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from the endpoint VLAN interfaces (VLAN/subnets).
- Permit (only as required for proper functionality) the specific system required signaling protocols used by the session manager ((e.g., H.323, SIP, AS-SIP) to/from the VVoIP core control equipment VLAN interfaces (VLAN/subnets).
- Deny all other traffic. End the ACL with a “deny all” statement.

If a deny-by-default ACL for session border VLAN interfaces is not implemented on VVoIP core routing devices as defined in the VVoIP system ACL design, this is a finding.'
  desc 'fix', 'Implement and document a deny-by-default ACL for session border VLAN interfaces on VVoIP core routing devices as defined in the VVoIP system ACL design as follows: 
- Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from the endpoint VLAN interfaces (VLAN/subnets).
- Permit (only as required for proper functionality) the specific system required signaling protocols used by the session manager ((e.g., H.323, SIP, AS-SIP) to/from the VVoIP core control equipment VLAN interfaces (VLAN/subnets).
- Deny all other traffic. End the ACL with a “deny all” statement.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23976r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19640'
  tag rid: 'SV-21781r3_rule'
  tag stig_id: 'VVoIP 5625'
  tag gtitle: 'VVoIP 5625'
  tag fix_id: 'F-20344r2_fix'
  tag 'documentable'
end
