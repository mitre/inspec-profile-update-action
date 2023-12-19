control 'SV-21629' do
  title 'The VVoIP system and supporting LAN design must contain one or more routing devices  to provide support for required ACLs between the various required VVoIP VLANs.'
  desc 'VLAN and IP address segmentation enables access and traffic control for the VVoIP system components. Only the required protocols are to reach a given VVoIP device thereby protecting it from non-essential protocols. This protection is afforded on the LAN by implementing ACLs based on VLAN/subnet, protocol and in some instances specific IP addresses. While a firewall placed between the core equipment and endpoint VLANs might provide better protection for the core equipment as a whole, a router is best suited to control the varying traffic patterns between the various devices. Normally a large B/C/P/S will have a large LAN and one or more LSCs supporting a large VVoIP phone system. In this case, it is within normal network design parameters to employ routing devices at the core of the LAN within the enclave. As such, the VVoIP system’s core equipment would be connected to these routing devices or have one or more routing devices of its own. 

NOTE: It is recognized that small LANs and enclaves may not support VVoIP phone system core equipment as would be the case if they used a “managed service” or a remote LSC. In such a LAN the number of VLANs might be limited to one for data and one for VoIP. Also, a small LAN may not have a router at its core, potentially due to cost, thereby not having the capability of supporting multiple VVoIP VLANs. In this case, this requirement does not apply and all VVoIP endpoints and local VVoIP infrastructure equipment would be in a single VLAN. However, the use of a Layer 3 LAN switch instead of a dedicated router may be a cost effective method to meet this requirement for small LANs.'
  desc 'check', 'Interview the IAO to confirm compliance with the following requirement: 

In the event the LAN supports VVoIP system core or infrastructure equipment or multiple VVoIP VLANs, ensure the  supporting LAN design contains one or more routing devices (router or layer 3 switch) to provide traffic control (support for required ACLs) between the various required VVoIP VLANs required for the core equipment. This device(s) should be as close to the VVoIP core equipment as possible.  As such this is the intersection of these VLANs. 
NOTE: this does not have to be one device but could be several, particularly if the VVoIP equipment is split and geographically diverse in support of system survivability.
NOTE: These devices may be (and typically will be) the core routing devices for the data LAN as well or may be dedicated to the VVoIP system.'
  desc 'fix', 'Ensure the VVoIP system and supporting LAN design contains one or more routing devices (router or layer 3 switch) to provide traffic control (support for required ACLs) between the various required VVoIP VLANs.

Install the required routing equipment as close to the VVoIP core equipment as is practical and apply the required ACLs.'
  impact 0.5
  ref 'DPMS Target IP Voice/Video/UC Site / System'
  tag check_id: 'C-23804r1_chk'
  tag severity: 'medium'
  tag gid: 'V-19565'
  tag rid: 'SV-21629r2_rule'
  tag stig_id: 'VVoIP 5510 (LAN)'
  tag gtitle: 'VVoIP Core ACL support'
  tag fix_id: 'F-20255r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'DCBP-1, DCPA-1, DCSP-1, ECSC-1'
end
