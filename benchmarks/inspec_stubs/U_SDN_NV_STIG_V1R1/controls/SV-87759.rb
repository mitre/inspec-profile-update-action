control 'SV-87759' do
  title 'All Virtual Extensible Local Area Network (VXLAN) enabled switches must be configured with the appropriate VXLAN network identifier (VNI) to ensure VMs can send and receive all associated traffic for their Layer 2 domain.'
  desc 'VXLAN is a Layer 2 network that overlays a Layer 3 network; that is, it creates a Layer 2 adjacency across a routed IP fabric. Each Layer 2 overlay network is known as a VXLAN segment and is identified by a unique segment ID called a VXLAN Network Identifier (VNI). 

The VXLAN network enables virtual machines with the same VNI deployed on different hosts to communicate with each other. Virtual machines are identified uniquely by the combination of the MAC addresses of their virtual network interface card (NIC) and VNI. Hence, it is possible to have duplicate MAC addresses within the SDN infrastructure while in different VXLAN segments. Within the VXLAN architecture, virtual tunnel endpoints (VTEPs) perform the encapsulation and de-encapsulation of the layer-2 traffic. The VXLAN segments are independent of the underlying network topology; conversely, the underlying IP network between VTEPs is independent of the VXLAN overlay. It routes the encapsulated packets based on the outer IP address header, which has the initiating VTEP as the source IP address and the terminating VTEP as the destination IP address. 

The VTEP must be configured with the appropriate VNIs to enable the VTEP to build forwarding tables for active VXLAN segments (Layer 2 domains) by learning MAC addresses per VNI packet flows.'
  desc 'check', 'Review the VXLAN topology and documentation for the SDN deployment that identifies each VXLAN segment and distributed logical switch. 

Review the configuration of all physical VXLAN-enabled switches to verify that the applicable VNIs are defined. 

If the applicable VNIs have not been defined on all VXLAN-enabled switches, this is a finding.

Note: This requirement is applicable to the implementation of technologies similar to VXLAN (e.g., NVGRE, STT) for the purpose of transporting traffic between virtual machines residing on different physical hosts.'
  desc 'fix', 'Define all applicable member VNIs on each VXLAN-enabled switch.'
  impact 0.5
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73241r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73107'
  tag rid: 'SV-87759r1_rule'
  tag stig_id: 'NET-SDN-020'
  tag gtitle: 'NET-SDN-020'
  tag fix_id: 'F-79553r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
