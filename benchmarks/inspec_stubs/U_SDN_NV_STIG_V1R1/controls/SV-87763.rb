control 'SV-87763' do
  title 'The proper multicast group for each Virtual Extensible Local Area Network (VXLAN) identifier must be mapped to the appropriate virtual tunnel endpoint (VTEP) so the VTEP will join the associated multicast groups.'
  desc 'VXLAN is a Layer 2 network that overlays a Layer 3 network; that is, it creates a Layer 2 adjacency across a routed IP fabric. Each Layer 2 overlay network is known as a VXLAN segment and is identified by a unique segment ID called a VXLAN Network Identifier (VNI). 

The VXLAN network enables virtual machines with the same VNI deployed on different hosts to communicate with each other. Virtual machines are identified uniquely by the combination of the MAC addresses of their virtual network interface card (NIC) and VNI. Hence, it is possible to have duplicate MAC addresses within the SDN infrastructure while in different VXLAN segments. Within the VXLAN architecture, VTEPs perform the encapsulation and de-encapsulation of the layer-2 traffic. The VXLAN segments are independent of the underlying network topology; conversely, the underlying IP network between VTEPs is independent of the VXLAN overlay. It routes the encapsulated packets based on the outer IP address header, which has the initiating VTEP as the source IP address and the terminating VTEP as the destination IP address.

Each VXLAN segment is mapped to an IP multicast group in the transport IP network. Hence, VTEPs join IP multicast groups based on VNI membership. This is the method by which VTEPs can discover other VTEPs belonging to the same VXLAN segment. Each VTEP-enabled switch is configured to join the applicable multicast group for each VNI through Internet Group Management Protocol (IGMP). The IGMP joins will trigger Protocol Independent Multicast (PIM) joins, thereby signaling a multicast distribution tree for each group through the transport network based on the locations of participating VTEPs.
The multicast group is used to transmit broadcast, unknown unicast, and multicast traffic through the IP network for each VXLAN segment, limiting all Layer 2 flooding to those switches that have end systems participating in the same VXLAN segment.

Because the VNI is used to segregate all Layer 2 domains via the VXLAN header encapsulation by the VTEPs, and discovery of each VTEP member is dependent on a specific multicast group, it is imperative that the correct mapping of multicast groups to VNI is configured.'
  desc 'check', 'Review the VXLAN topology as well as documentation for the SDN deployment that identifies each VXLAN segment via VNI and the associated multicast groups. 

Review the VTEP configuration of all physical VXLAN-enabled switches to verify that the appropriate multicast group is defined for each VNI. 

If the appropriate multicast group is not configured for each member VNI, this is a finding.

Note: This requirement is only applicable to VNIs that must be defined on each VXLAN-enabled switch. In addition, this requirement is applicable to the implementation of technologies similar to VXLAN (e.g., NVGRE, STT) for the purpose of transporting traffic between virtual machines residing on different physical hosts.'
  desc 'fix', 'Configure the appropriate multicast group that is assigned to each VNI on all VXLAN-enabled switches.'
  impact 0.5
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73245r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73111'
  tag rid: 'SV-87763r1_rule'
  tag stig_id: 'NET-SDN-022'
  tag gtitle: 'NET-SDN-022'
  tag fix_id: 'F-79557r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
