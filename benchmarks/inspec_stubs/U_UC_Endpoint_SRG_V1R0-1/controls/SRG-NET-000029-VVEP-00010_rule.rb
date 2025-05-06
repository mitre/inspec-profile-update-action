control 'SRG-NET-000029-VVEP-00010_rule' do
  title 'The Unified Communications Endpoint must be configured to apply 802.1Q VLAN tags to signaling and media traffic.'
  desc 'When Unified Communications Endpoints do not dynamically assign 802.1Q VLAN tags as data is created and combined, it is possible the VLAN tags will not correctly reflect the data type with which they are associated. VLAN tags are used as security attributes. These attributes are typically associated with signaling and media streams within the application and are used to enable the implementation of access control and flow control policies. Security labels for packets may include traffic flow information (e.g., source, destination, protocol combination), traffic classification based on QoS markings for preferred treatment, and VLAN identification.

Virtualized networking is used to separate voice video traffic from other types of traffic, such as data, management, and other special types. VLANs provide segmentation at layer 2. Virtual Routing and Forwarding (VRF) provides segmentation at layer 3 and works with Multiprotocol Label Switching (MPLS) for enterprise and WAN environments. When VRF is used without MPLS, it is referred to as VRF lite. For Voice Video systems, subnets, VLANs, and VRFs are used to separate media and signaling streams from all other traffic.'
  desc 'check', 'Verify the Unified Communications Endpoint is configured to apply 802.1Q VLAN tags to signaling and media traffic. 

If the Unified Communications Endpoint does not apply 802.1Q VLAN tags to signaling and media traffic, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to apply 802.1Q VLAN tags to signaling and media traffic.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000029-VVEP-00010_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000029-VVEP-00010'
  tag rid: 'SRG-NET-000029-VVEP-00010_rule'
  tag stig_id: 'SRG-NET-000029-VVEP-00010'
  tag gtitle: 'SRG-NET-000029-VVEP-00010'
  tag fix_id: 'F-SRG-NET-000029-VVEP-00010_fix'
  tag 'documentable'
  tag cci: ['CCI-000027']
  tag nist: ['AC-4 (3)']
end
