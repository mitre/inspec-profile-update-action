control 'SV-75805' do
  title 'The VVoIP system management network bidirectional enclave boundary protection between the local management network and the DISN voice services management network must be scanned to confirm protections in place are effective.'
  desc 'VVoIP core system devices and Time Division Multiplexer (TDM)-based telecom switches can be and in many cases are connected to multiple management networks. Such is the case when the system is managed by local SAs and systems via the local management VLAN or dedicated OOB management network and other SAs or systems manage or monitor the system via another network such as a remote MILDEP NOC, the DSN’s ADIMSS network, the RTS EMS, or the DISN DCN. A similar situation occurs in the DRSN with the ARDIMSS network. In some cases, these networks are interconnected such that both management networks have access to the same devices via a single management port. Each of these management networks is in reality a different enclave and as such access and traffic between them must be filtered thus protecting each of the enclaves from compromise from one of the others. Enclaves are defined as a collection of computing environments connected by one or more internal networks under the control of a single authority and security policy, including personnel and physical security. Based on this definition, the local LAN enclave, remote MILDEP NOC, the DSN’s ADIMSS network, the RTS EMS, and the DISN DCN are different enclaves. Therefore, minimally, a firewall is required where these enclaves meet.'
  desc 'check', 'Review site documentation to confirm that the VVoIP system management network bidirectional enclave boundary protection between the local management network and the DISN voice services management network has been scanned to confirm protections in place are effective. Validate the effectiveness of the boundary protection ACLs by performing network vulnerability scans as follows:
 - Scan the entire DISN management network (e.g., RTS EMS, ADIMSS, ARDIMSS, or DCN) address space from an unused randomly selected IP address on the local management network. 
 - Scan the entire local management network address space from an unused randomly selected IP address on the DISN management network.

If the VVoIP system management network bidirectional enclave boundary protection between the local management network and the DISN voice services management network has not been scanned to confirm protections in place are effective, this is a finding. If the network vulnerability scan receives a response from any host on either network, this is a finding.'
  desc 'fix', 'Implement and document that the VVoIP system management network bidirectional enclave boundary protection between the local management network and the DISN voice services management network has been scanned to confirm protections in place are effective. Validate the effectiveness of the boundary protection on an annual basis.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-62277r1_chk'
  tag severity: 'low'
  tag gid: 'V-61325'
  tag rid: 'SV-75805r1_rule'
  tag stig_id: 'VVoIP 5420'
  tag gtitle: 'VVoIP 5420'
  tag fix_id: 'F-67225r1_fix'
  tag 'documentable'
end
