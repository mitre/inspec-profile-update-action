control 'SV-21610' do
  title 'The VVoIP system management network must provide bidirectional enclave boundary protection between the local management network and the DISN voice services management network.'
  desc 'VVoIP core system devices and Time Division Multiplexer (TDM)-based telecom switches can be and in many cases are connected to multiple management networks. Such is the case when the system is managed by local SAs and systems via the local management VLAN or dedicated OOB management network and other SAs or systems manage or monitor the system via another network such as a remote MILDEP NOC, the DSN’s ADIMSS network, the RTS EMS, or the DISN DCN. A similar situation occurs in the DRSN with the ARDIMSS network. In some cases, these networks are interconnected such that both management networks have access to the same devices via a single management port. Each of these management networks is in reality a different enclave and as such, access and traffic between them must be filtered thus protecting each of the enclaves from compromise from one of the others. Enclaves are defined as a collection of computing environments connected by one or more internal networks under the control of a single authority and security policy, including personnel and physical security. Based on this definition, the local LAN enclave, remote MILDEP NOC, the DSN’s ADIMSS network, the RTS EMS, and the DISN DCN are different enclaves. Therefore, minimally, a firewall is required where these enclaves meet.'
  desc 'check', 'Review site documentation to confirm the VVoIP system management network provides bidirectional enclave boundary protection between the local management network and the DISN voice services management network. This requirement is applicable to VVoIP core system devices and TDM based telecom switches managed via multiple networks and those managed via a single physical Ethernet IP interface. For example, when the ADIMSS and local SAs both manage a VVoIP system or device via a common pathway such as the local management VLAN or OOB management network, a firewall is required between the local network and the ADIMSS network. 

Determine who owns and is responsible for the enclave boundary protection device configuration and management. This device may be owned and operated by the DISN management network or the local network. Two such devices may be owned and operated by each entity.

If the VVoIP system management network does not provide bidirectional enclave boundary protection between the local management network and the DISN voice services management network, this is a finding.'
  desc 'fix', 'Implement and document the VVoIP system management network to provide bidirectional enclave boundary protection between the local management network and the DISN voice services management network.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23797r4_chk'
  tag severity: 'medium'
  tag gid: 'V-19547'
  tag rid: 'SV-21610r3_rule'
  tag stig_id: 'VVoIP 5405'
  tag gtitle: 'VVoIP 5405'
  tag fix_id: 'F-20249r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
end
