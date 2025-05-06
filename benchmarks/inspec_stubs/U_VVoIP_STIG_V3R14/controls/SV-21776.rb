control 'SV-21776' do
  title 'A deny-by-default ACL for VVoIP endpoint VLAN interfaces must be implemented on VVoIP core routing devices as defined in the VVoIP system ACL design.'
  desc 'Router ACLs are required to control access and the flow of traffic to and from VVoIP system devices and their VLANs as a protection mechanism. In general the defined ACLs are designed in a deny-by-default manner such that only the protocols and traffic that needs to reach the device or devices in the VLAN receive the packets. The ACLs filter on VLAN, IP address and subnet, protocol type, and associated standard IP port for the protocol. In general, the ACLs mentioned are egress filters (referenced the router core) on the VLAN interfaces. Additionally, the routing devices should log and alarm on inappropriate traffic. An example of this is an HTTP request sourced from the data VLANs to the endpoint or media gateway VLANs. The primary purpose of ACL on all VVoIP VLAN interfaces is to block traffic to or from the data VLAN interfaces. Similar restrictions are placed on a dedicated VTC VLAN interface, however, VVoIP media and signaling is permitted in the event a VTC unit needs to communicate with the UC system.'
  desc 'check', 'Review site documentation, especially the VVoIP system ACL design,  to confirm a deny-by-default ACL for VVoIP endpoint VLAN interfaces is implemented on VVoIP core routing devices.  Ensure a deny-by-default ACL is implemented on all VVoIP endpoint (hardware and software) VLAN interfaces at the VVoIP core routing device to control traffic as follows: 
- Endpoint configuration and registration - Permit (only as required for proper functionality) the specific system required endpoint registration / configuration protocols/traffic (e.g., DHCP, BootP, TFTP, FTP, HTTP, DNS, etc.) to/from the core control equipment VLAN interfaces (VLAN/subnet). 
- Endpoint Signaling - Permit (only as required for proper functionality) the specific system required endpoint signaling protocols/traffic (e.g., AS-SIP, H.323, vendor proprietary such as SCCP, UniStim, etc.) to/from the core control equipment VLAN interfaces (VLAN/subnets). 
- Endpoint Directory - Permit (only as required for proper functionality) the specific system required endpoint directory access protocols (e.g., HTTP and/or potentially others) to/from the core control equipment VLAN interfaces.
- Endpoint Media - Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from the Media Gateway VLAN interfaces (VLAN/subnets).
- Endpoint Media - Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from the Voicemail/Unified Messaging VLAN interfaces (VLAN/subnets).
- Endpoint Media - Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from other endpoint VLAN interfaces (VLAN/subnets) wherever they intersect. 
- Deny all other traffic. End the ACL with a “deny all” statement.

If a deny-by-default ACL for VVoIP endpoint VLAN interfaces is not implemented on VVoIP core routing devices as defined in the VVoIP system ACL design, this is a finding.'
  desc 'fix', 'Implement and document a deny-by-default ACL for VVoIP endpoint VLAN interfaces on VVoIP core routing devices as defined in the VVoIP system ACL design as follows: 
- Endpoint configuration and registration - Permit (only as required for proper functionality) the specific system required endpoint registration / configuration protocols/traffic (e.g., DHCP, BootP, TFTP, FTP, HTTP, DNS, etc.) to/from the core control equipment VLAN interfaces (VLAN/subnet). 
- Endpoint Signaling - Permit (only as required for proper functionality) the specific system required endpoint signaling protocols/traffic (e.g., AS-SIP, H.323, vendor proprietary such as SCCP, UniStim, etc.) to/from the core control equipment VLAN interfaces (VLAN/subnets). 
- Endpoint Directory - Permit (only as required for proper functionality) the specific system required endpoint directory access protocols (e.g., HTTP and/or potentially others) to/from the core control equipment VLAN interfaces.
- Endpoint Media - Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from the Media Gateway VLAN interfaces (VLAN/subnets).
- Endpoint Media - Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from the Voicemail/Unified Messaging VLAN interfaces (VLAN/subnets).
- Endpoint Media - Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from other endpoint VLAN interfaces (VLAN/subnets) wherever they intersect. 
- Deny all other traffic. End the ACL with a “deny all” statement.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23961r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19635'
  tag rid: 'SV-21776r3_rule'
  tag stig_id: 'VVoIP 5600'
  tag gtitle: 'VVoIP 5600'
  tag fix_id: 'F-20339r2_fix'
  tag 'documentable'
end
