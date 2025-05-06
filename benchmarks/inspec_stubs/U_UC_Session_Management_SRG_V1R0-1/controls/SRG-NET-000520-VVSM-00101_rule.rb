control 'SRG-NET-000520-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to apply 802.1Q VLAN tags to signaling and media traffic.'
  desc 'When network elements do not dynamically reconfigure the data security attributes as data is created and combined, the possibility exists that security attributes will not correctly reflect the data with which they are associated. For the Unified Communications Session Manager, the use of 802.1q tags on media and signaling, and the use of VLANs provides this layer of security. VLANs facilitate access and traffic control for voice video system components and enhanced QoS.

Virtualized networking is used to separate voice video traffic from other types of traffic, such as data, management, and other special types. VLANs provide segmentation at layer 2. Virtual Routing and Forwarding (VRF) provides segmentation at layer 3 and works with Multiprotocol Label Switching (MPLS) for enterprise and WAN environments. When VRF is used without MPLS, it is referred to as VRF lite. For Voice Video systems, subnets, VLANs, and VRFs are used to separate media and signaling streams from all other traffic.'
  desc 'check', 'Verify the Unified Communications Session Manager applies 802.1Q VLAN tags to signaling and media traffic.

If the Unified Communications Session Manager does not apply 802.1Q VLAN tags to signaling and media traffic, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to apply 802.1Q VLAN tags to signaling and media traffic or be in a private subnet.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000520-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000520-VVSM-00101'
  tag rid: 'SRG-NET-000520-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000520-VVSM-00101'
  tag gtitle: 'SRG-NET-000520-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000520-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-002272']
  tag nist: ['AC-16 (1)']
end
