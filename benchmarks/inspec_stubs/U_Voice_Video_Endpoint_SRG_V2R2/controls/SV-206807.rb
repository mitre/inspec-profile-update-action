control 'SV-206807' do
  title 'The hardware Voice Video Endpoint must apply 802.1Q VLAN tags to signaling and media traffic.'
  desc 'When Voice Video Endpoints do not dynamically assign 802.1Q VLAN tags as data is created and combined, it is possible the VLAN tags will not correctly reflect the data type with which they are associated. VLAN tags are used as security attributes. These attributes are typically associated with signaling and media streams within the application and are used to enable the implementation of access control and flow control policies. Security labels for packets may include traffic flow information (e.g., source, destination, protocol combination), traffic classification based on QoS markings for preferred treatment, and VLAN identification.

Virtualized networking is used to separate voice video traffic from other types of traffic, such as data, management, and other special types. VLANs provide segmentation at layer 2. Virtual Routing and Forwarding (VRF) provides segmentation at layer 3, and works with Multiprotocol Label Switching (MPLS) for enterprise and WAN environments. When VRF is used without MPLS, it is referred to as VRF lite. For Voice Video systems, subnets, VLANs, and VRFs are used to separate media and signaling streams from all other traffic.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint, this check procedure is Not Applicable.

Verify the hardware Voice Video Endpoint applies 802.1Q VLAN tags to signaling and media traffic. 

If the hardware Voice Video Endpoint does not apply 802.1Q VLAN tags to signaling and media traffic, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint to apply 802.1Q VLAN tags to signaling and media traffic.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7063r363944_chk'
  tag severity: 'medium'
  tag gid: 'V-206807'
  tag rid: 'SV-206807r604140_rule'
  tag stig_id: 'SRG-NET-000520-VVEP-00010'
  tag gtitle: 'SRG-NET-000520'
  tag fix_id: 'F-7063r363945_fix'
  tag 'documentable'
  tag legacy: ['V-66701', 'SV-81191']
  tag cci: ['CCI-000366', 'CCI-002272']
  tag nist: ['CM-6 b', 'AC-16 (1)']
end
