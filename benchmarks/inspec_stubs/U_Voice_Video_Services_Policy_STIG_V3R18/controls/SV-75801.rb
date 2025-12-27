control 'SV-75801' do
  title 'The VVoIP system management network with a single device providing bidirectional enclave boundary protection between the local management network and the DISN voice services management network must have a Memorandum of Agreement (MoA) in effect.'
  desc 'VVoIP core system devices and Time Division Multiplexer (TDM)-based telecom switches can be and in many cases are connected to multiple management networks. Such is the case when the system is managed by local SAs and systems via the local management VLAN or dedicated OOB management network and other SAs or systems manage or monitor the system via another network such as a remote MILDEP NOC, the DSN’s ADIMSS network, the RTS EMS, or the DISN DCN. A similar situation occurs in the DRSN with the ARDIMSS network. In some cases, these networks are interconnected such that both management networks have access to the same devices via a single management port. Each of these management networks is in reality a different enclave and as such, access and traffic between them must be filtered thus protecting each of the enclaves from compromise from one of the others. Enclaves are defined as a collection of computing environments connected by one or more internal networks under the control of a single authority and security policy, including personnel and physical security. Based on this definition, the local LAN enclave, remote MILDEP NOC, the DSN’s ADIMSS network, the RTS EMS, and the DISN DCN are different enclaves. Therefore, minimally a firewall is required where these enclaves meet.'
  desc 'check', 'Review site documentation to confirm that the VVoIP system management network with a single device providing bidirectional enclave boundary protection between the local management network and the DISN voice services management network has a MoA signed by both parties in effect. The MoA must stipulate the conditions of operation of the device such that the owner implements a configuration that not only protects the owner’s network but also protects the other’s network. Further validate that both parties have agreed to and signed the MoA. If there is no such MoA, the respective owners may need to implement their own devices. If the VVoIP system management network with a single device providing bidirectional enclave boundary protection between the local management network and the DISN voice services management network does not have a MoA signed by both parties in effect, this is a finding.'
  desc 'fix', 'Implement and document that the VVoIP system management network with a single device providing bidirectional enclave boundary protection between the local management network and the DISN voice services management network has a MoA signed by both parties in effect.'
  impact 0.3
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-62273r1_chk'
  tag severity: 'low'
  tag gid: 'V-61321'
  tag rid: 'SV-75801r1_rule'
  tag stig_id: 'VVoIP 5410'
  tag gtitle: 'VVoIP 5410'
  tag fix_id: 'F-67221r1_fix'
  tag 'documentable'
  tag ia_controls: 'EBBD-2, ECSC-1'
end
