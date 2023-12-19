control 'SV-21778' do
  title 'A deny-by-default ACL for session manager VLAN interfaces must be implemented on VVoIP core routing devices as defined in the VVoIP system ACL design.'
  desc 'Router ACLs are required to control access and the flow of traffic to and from VVoIP system devices and their VLANs as a protection mechanism. In general, the defined ACLs are designed in a deny-by-default manner such that only the protocols and traffic that needs to reach the device or devices in the VLAN receive the packets. The ACLs filter on VLAN, IP address and subnet, protocol type, and associated standard IP port for the protocol. In general, the ACLs mentioned are egress filters (referenced the router core) on the VLAN interfaces. Additionally, the routing devices should send an alarm in response to inappropriate traffic and log the occurrence. An example of this is an HTTP request sourced from the data VLANs to the endpoint or media gateway VLANs. The primary purpose of ACL on all VVoIP VLAN interfaces is to block traffic to or from the data VLAN interfaces. Similar restrictions are placed on a dedicated VTC VLAN interface, however, VVoIP media and signaling is permitted in the event a VTC unit needs to communicate with the UC system.'
  desc 'check', 'Review site documentation, especially the VVoIP system ACL design, to confirm a deny-by-default ACL for session manager VLAN interfaces is implemented on VVoIP core routing devices. Ensure a deny-by-default ACL is implemented on the VVoIP session manager VLAN interfaces on the VVoIP routing devices supporting the VVoIP system core equipment to control traffic as follows: 
- Endpoint configuration - Permit (only as required for proper functionality) the specific system required endpoint registration / configuration protocols/traffic (e.g., DHCP, BootP, TFTP, FTP, HTTP, DNS, etc.) to/from the endpoint VLAN interfaces (VLAN/subnets). 
- Endpoint signaling - Permit (only as required for proper functionality) the specific system required endpoint signaling protocols/traffic (e.g., AS-SIP, H.323, vendor proprietary such as SCCP, UniStim, etc.) to/from the endpoint VLAN interfaces (VLAN/subnets). 
- Endpoint directory - Permit (only as required for proper functionality) the specific system required endpoint directory access protocols (e.g., HTTP and/or potentially others) to/from the endpoint VLAN interfaces. 
- Media gateway - Permit (only as required for proper functionality) the specific system required signaling protocols used by the media gateway (e.g., MGCP, H.248, H.323, AS-SIP) to/from the VVoIP media gateway VLAN interfaces (VLAN/subnets).
- Signaling gateway - Permit (only as required for proper functionality and the VLAN exists) the specific system required signaling protocols used by the signaling gateway (e.g., MGCP, H.248, H.323, AS-SIP) to/from the VVoIP signaling gateway VLAN interfaces (VLAN/subnets)
- Session border controller - Permit (only as required for proper functionality and the VLAN exists) the specific signaling protocols used by the Edge Boundary Controller (AS-SIP) to/from the VVoIP session border controller VLAN interfaces (VLANs / subnet).
- Customer edge router - Permit (only as required for proper functionality) the specific signaling or management protocols used to communicate with the Customer Edge (Premises / enclave perimeter) Router for NETOPS etc. (e.g., SNMP and potentially others) to/from the VVoIP data mgmt VLAN interfaces, OOB management LAN, or data network VLAN interfaces (VLANs / subnet) via data mgmt VLAN, OOB management LAN, or data network.
- Voicemail/Unified messaging - Permit the specific signaling protocols used by the Voicemail/Unified Messaging servers (e.g., AS-SIP, H.323, vendor proprietary such as SCCP, UniStim, etc.) to/from the VVoIP Voicemail or Unified Messaging server VLAN interfaces (VLANs / subnet).
- Unified capabilities - Permit (only as required for proper functionality and the VLAN exists) the specific signaling protocols used by any unified communications servers (e.g., AS-SIP, H.323, vendor proprietary such as SCCP, UniStim, etc.) to/from the VVoIP UC server VLAN interfaces (VLANs / subnet).
- Permit Media protocols (RTP/RTCP, SRTP/SRTCP) to/from the endpoint VLAN interfaces, media gateway VLAN interfaces, and voicemail/unified messaging VLAN interfaces (VLAN/subnets). (Call control equipment does not typically process media therefore there is typically no need to permit this traffic and thereby provide a potential attack vector.)
- Permit only those other protocols/traffic between specific VLANs, subnets, and devices as required for the system to properly function. 
- Deny all other traffic. End the ACL with a “deny all” statement.
NOTE: The ACLs must mirror the ACLs imposed for access to/from each of the mating VLANs based on the protocols that VLAN accepts. 

If a deny-by-default ACL for session manager VLAN interfaces is not implemented on VVoIP core routing devices as defined in the VVoIP system ACL design, this is a finding.'
  desc 'fix', 'Implement and document a deny-by-default ACL for session manager VLAN interfaces on VVoIP core routing devices as defined in the VVoIP system ACL design as follows: 
- Endpoint configuration - Permit (only as required for proper functionality) the specific system required endpoint registration / configuration protocols/traffic (e.g., DHCP, BootP, TFTP, FTP, HTTP, DNS, etc.) to/from the endpoint VLAN interfaces (VLAN/subnets). 
- Endpoint signaling - Permit (only as required for proper functionality) the specific system required endpoint signaling protocols/traffic (e.g., AS-SIP, H.323, vendor proprietary such as SCCP, UniStim, etc.) to/from the endpoint VLAN interfaces (VLAN/subnets). 
- Endpoint directory - Permit (only as required for proper functionality) the specific system required endpoint directory access protocols (e.g., HTTP and/or potentially others) to/from the endpoint VLAN interfaces. 
 - Media gateway - Permit (only as required for proper functionality) the specific system required signaling protocols used by the media gateway (e.g., MGCP, H.248, H.323, AS-SIP) to/from the VVoIP media gateway VLAN interfaces (VLAN/subnets).
- Signaling gateway - Permit (only as required for proper functionality and the VLAN exists) the specific system required signaling protocols used by the signaling gateway (e.g., MGCP, H.248, H.323, AS-SIP) to/from the VVoIP signaling gateway VLAN interfaces (VLAN/subnets)
- Session border controller - Permit (only as required for proper functionality and the VLAN exists) the specific signaling protocols used by the Edge Boundary Controller (AS-SIP) to/from the VVoIP session border controller VLAN interfaces (VLANs / subnet).
- Customer edge router - Permit (only as required for proper functionality) the specific signaling or management protocols used to communicate with the Customer Edge (Premises / enclave perimeter) Router for NETOPS etc. (e.g., SNMP and potentially others) to/from the VVoIP data mgmt VLAN interfaces, OOB management LAN, or data network VLAN interfaces (VLANs / subnet) via data mgmt VLAN, OOB management LAN, or data network.
- Unified messaging - Permit the specific signaling protocols used by the Voicemail/Unified Messaging servers (e.g., AS-SIP, H.323, vendor proprietary such as SCCP, UniStim, etc.) to/from the VVoIP Voicemail or Unified Messaging server VLAN interfaces (VLANs / subnet).
- Unified capabilities - Permit (only as required for proper functionality and the VLAN exists) the specific signaling protocols used by any unified communications servers (e.g., AS-SIP, H.323, vendor proprietary such as SCCP, UniStim, etc.) to/from the VVoIP UC server VLAN interfaces (VLANs / subnet).
- Permit Media protocols (RTP/RTCP, SRTP/SRTCP) to/from the endpoint VLAN interfaces, media gateway VLAN interfaces, and voicemail/unified messaging VLAN interfaces (VLAN/subnets).  (Call control equipment does not typically process media therefore there is typically no need to permit this traffic and thereby provide a potential attack vector.)
- Permit only those other protocols/traffic between specific VLANs, subnets, and devices as required for the system to properly function. 
- Deny all other traffic. End the ACL with a “deny all” statement.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-23967r2_chk'
  tag severity: 'medium'
  tag gid: 'V-19637'
  tag rid: 'SV-21778r3_rule'
  tag stig_id: 'VVoIP 5610'
  tag gtitle: 'VVoIP 5610'
  tag fix_id: 'F-20341r2_fix'
  tag 'documentable'
end
