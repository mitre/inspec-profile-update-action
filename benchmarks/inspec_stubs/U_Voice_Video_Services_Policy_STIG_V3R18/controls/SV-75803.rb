control 'SV-75803' do
  title 'The VVoIP system management network bidirectional enclave boundary protection between the local management network and the DISN voice services management network must have ACLs permitting only specific inbound/outbound traffic and deny all other traffic.'
  desc 'VVoIP core system devices and Time Division Multiplexer (TDM)-based telecom switches can be and in many cases are connected to multiple management networks. Such is the case when the system is managed by local SAs and systems via the local management VLAN or dedicated OOB management network and other SAs or systems manage or monitor the system via another network such as a remote MILDEP NOC, the DSN’s ADIMSS network, the RTS EMS, or the DISN DCN. A similar situation occurs in the DRSN with the ARDIMSS network. In some cases, these networks are interconnected such that both management networks have access to the same devices via a single management port. Each of these management networks is in reality a different enclave and as such, access and traffic between them must be filtered thus protecting each of the enclaves from compromise from one of the others. Enclaves are defined as a collection of computing environments connected by one or more internal networks under the control of a single authority and security policy, including personnel and physical security. Based on this definition, the local LAN enclave, remote MILDEP NOC, the DSN’s ADIMSS network, the RTS EMS, and the DISN DCN are different enclaves. Therefore, minimally, a firewall is required where these enclaves meet.'
  desc 'check', 'Review site documentation to confirm that the VVoIP system management network bidirectional enclave boundary protection between the local management network and the DISN voice services management network has ACLs permitting only specific inbound/outbound traffic and deny all other traffic. Enclave boundary protection must be implemented at the entry point of the DISN management network to Inspect the ACLs on the boundary protection devices to ensure a deny-by-default posture allowing only specifically required protocol traffic between specific pairs of IP addresses across the boundary. 

The inbound ACL must include:
 - The ability to permit the specifically authorized and required protocol sourced from the IP address of the specifically authorized device on the DISN management network to reach the specific IP address of the managed device or required local management server.
 - Additional statements for each protocol and IP address pair.
 - Deny all other traffic.

The outbound ACL must include:
 - The ability to permit the specifically authorized and required protocol sourced from the specific IP address of the managed device or any required local management server to reach the specific IP address of the specifically authorized device on the DISN management network.
 - Additional statements for each protocol and IP address pair.
 - Deny all other traffic.

If the VVoIP system management network bidirectional enclave boundary protection between the local management network and the DISN voice services management network does not have ACLs permitting only specific inbound/outbound traffic and deny all other traffic as indicated above, this is a finding.'
  desc 'fix', 'Implement and document that the VVoIP system management network bidirectional enclave boundary protection between the local management network and the DISN voice services management network has ACLs permitting only specific inbound/outbound traffic and deny all other traffic.

The inbound ACL must include:
 - The ability to permit the specifically authorized and required protocol sourced from the IP address of the specifically authorized device on the DISN management network to reach the specific IP address of the managed device or required local management server.
 - Additional statements for each protocol and IP address pair.
 - Deny all other traffic.

The outbound ACL must include:
 - The ability to permit the specifically authorized and required protocol sourced from the specific IP address of the managed device or any required local management server to reach the specific IP address of the specifically authorized device on the DISN management network.
 - Additional statements for each protocol and IP address pair.
 - Deny all other traffic.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-62275r1_chk'
  tag severity: 'low'
  tag gid: 'V-61323'
  tag rid: 'SV-75803r1_rule'
  tag stig_id: 'VVoIP 5415'
  tag gtitle: 'VVoIP 5415'
  tag fix_id: 'F-67223r1_fix'
  tag 'documentable'
  tag ia_controls: 'EBBD-2, ECSC-1'
end
