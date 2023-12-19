control 'SV-21783' do
  title 'A deny-by-default ACL for voicemail and unified messaging servers VLAN interfaces must be implemented on core routing devices as defined in the VVoIP system ACL design.'
  desc 'Router ACLs are required to control access and the flow of traffic to and from VVoIP system devices and their VLANs as a protection mechanism. In general, the defined ACLs are designed in a deny-by-default manner such that only the protocols and traffic that needs to reach the device or devices in the VLAN receive the packets. The ACLs filter on VLAN, IP address and subnet, protocol type, and associated standard IP port for the protocol. In general, the ACLs mentioned are egress filters (referenced the router core) on the VLAN interfaces. Additionally, the routing devices should log and alarm on inappropriate traffic. An example of this is an HTTP request sourced from the data VLANs to the endpoint or media gateway VLANs. The primary purpose of ACL on all VVoIP VLAN interfaces is to block traffic to or from the data VLAN interfaces. Similar restrictions are placed on a dedicated VTC VLAN interface, however, VVoIP media and signaling is permitted in the event a VTC unit needs to communicate with the UC system.'
  desc 'check', 'Review site documentation, especially the VVoIP system ACL design, to confirm a deny-by-default ACL for voicemail and unified messaging servers VLAN interfaces must be implemented on core routing devices as defined in the VVoIP system ACL design. Ensure a deny-by-default ACL is implemented on the VVoIP Voicemail / Unified Messaging Servers VLAN interfaces on the VVoIP routing devices supporting the VVoIP system core equipment to control traffic as follows: 
- Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from the endpoint VLAN interfaces (VLAN/subnets) (for depositing and retrieving VM from internal endpoints).
- Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from the Media Gateway VLAN interfaces (VLAN/subnets) ((for depositing and retrieving VM from outside the enclave via a TDM network).
- Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from the DoD WAN access VVoIP firewall (session border controller or other) VLAN interfaces (VLAN/subnets) (for depositing and retrieving VM from outside the enclave via an IP network).
- Permit (only as required for proper functionality) the specific system required signaling protocols used by the Voicemail / Unified Messaging Servers (e.g., H.323, SIP, AS-SIP, proprietary) to/from the VVoIP core control equipment VLAN interfaces (VLAN/subnets) (for session manager VM call setup/teardown).
- Permit (only as required for proper functionality) the specific system required protocols used by a VM server to send email attachments (e.g., SMTP) to the user’s email server to/from the VVoIP general data user VLAN interfaces (VLAN/subnets) (for retrieving VM via email from a PC).
- Permit (only as required for proper functionality) the specific system required protocols used by a user’s Unified Messaging client application on their PC (e.g., SMTP) to/from the VVoIP general data user VLAN interfaces (VLAN/subnets) (for retrieving email and VM from a PC in the event the VM server is also the user’s email server). 
- Deny all other traffic. End the ACL with a “deny all” statement.

If a deny-by-default ACL for voicemail and unified messaging servers VLAN interfaces is not implemented on core routing devices as defined in the VVoIP system ACL design, this is a finding.'
  desc 'fix', 'Implement and document a deny-by-default ACL for voicemail and unified messaging servers VLAN interfaces must be implemented on core routing devices as defined in the VVoIP system ACL design.  as follows: 
- Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from the endpoint VLAN interfaces (VLAN/subnets).
- Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from the Media Gateway VLAN interfaces (VLAN/subnets).
- Permit Media protocols/traffic (RTP/RTCP, SRTP/SRTCP) to/from the DoD WAN access VVoIP firewall (session border controller or other) VLAN interfaces (VLAN/subnets).
- Permit (only as required for proper functionality) the specific system required signaling protocols used by the Voicemail / Unified Messaging Servers (e.g., H.323, SIP, AS-SIP, proprietary) to/from the VVoIP core control equipment VLAN interfaces (VLAN/subnets).
- Permit (only as required for proper functionality) the specific system required protocols used by a user’s Unified Messaging client application (e.g., SMTP) to/from the VVoIP general data user VLAN interfaces (VLAN/subnets).
- Deny all other traffic. End the ACL with a “deny all” statement.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23982r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19642'
  tag rid: 'SV-21783r3_rule'
  tag stig_id: 'VVoIP 5635'
  tag gtitle: 'VVoIP 5635'
  tag fix_id: 'F-20346r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
