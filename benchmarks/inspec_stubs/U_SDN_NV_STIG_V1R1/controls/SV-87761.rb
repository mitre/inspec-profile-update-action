control 'SV-87761' do
  title 'Virtual Extensible Local Area Network (VXLAN) identifiers must be mapped to the appropriate VLAN identifiers.'
  desc 'VXLAN is a Layer 2 network that overlays a Layer 3 network; that is, it creates a Layer 2 adjacency across a routed IP fabric. Each Layer 2 overlay network is known as a VXLAN segment and is identified by a unique segment ID called a VXLAN Network Identifier (VNI). 

The VXLAN network enables virtual machines with the same VNI deployed on different hosts to communicate with each other. Virtual machines are identified uniquely by the combination of the MAC addresses of their virtual network interface card (NIC) and VNI. Hence, it is possible to have duplicate MAC addresses within the SDN infrastructure while in different VXLAN segments. Within the VXLAN architecture, virtual tunnel endpoints (VTEPs) perform the encapsulation and de-encapsulation of the layer-2 traffic. The VXLAN segments are independent of the underlying network topology; conversely, the underlying IP network between VTEPs is independent of the VXLAN overlay. It routes the encapsulated packets based on the outer IP address header, which has the initiating VTEP as the source IP address and the terminating VTEP as the destination IP address.

VTEP-enabled switches will determine the VNI to insert into the VXLAN header based on the 802.1Q VLAN tag of each frame received from the hypervisor host connected via trunk link or the VLAN assignment of an access switchport. The mapping of VLAN to VNI is configured on the switch. Since the VNI is used to segregate all Layer 2 domains, the correct mapping is critical to ensure all traffic for each Layer 2 domain within the SDN infrastructure is forwarded correctly and that broadcast and multicast traffic does not leak into the wrong domain.'
  desc 'check', 'Review the VXLAN topology and documentation for the SDN deployment that identifies each VXLAN segment via VNI, VLAN membership, and the VLAN-to-VNI mapping to be implemented. 

Review the VTEP configuration of all physical VXLAN-enabled switches to verify that the appropriate VLAN-to-VNI mapping has been defined. 

If the correct VLAN-to-VNI mapping has not been configured on all VXLAN-enabled switches, this is a finding.

Note: This requirement is only applicable to VNIs that must be defined on each VXLAN-enabled switch. In addition, this requirement is applicable to the implementation of technologies similar to VXLAN (e.g., NVGRE, STT) for the purpose of transporting traffic between virtual machines residing on different physical hosts.'
  desc 'fix', 'Configure the appropriate VLAN-to-VNI mapping on all VXLAN-enabled switches.'
  impact 0.5
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73243r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73109'
  tag rid: 'SV-87761r1_rule'
  tag stig_id: 'NET-SDN-021'
  tag gtitle: 'NET-SDN-021'
  tag fix_id: 'F-79555r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
