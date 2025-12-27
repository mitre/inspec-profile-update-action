control 'SV-206861' do
  title 'The Voice Video Session Manager must apply 802.1Q VLAN tags to signaling and media traffic or be in a private subnet.'
  desc 'When network elements do not dynamically reconfigure the data security attributes as data is created and combined, the possibility exists that security attributes will not correctly reflect the data with which they are associated. For the Voice Video Session Manager, the use of 802.1q tags on media and signaling, and the use of VLANs provides this layer of security. VLANs facilitate access and traffic control for voice video system components and enhanced QoS.

Virtualized networking is used to separate voice video traffic from other types of traffic, such as data, management, and other special types. VLANs provide segmentation at layer 2. Virtual Routing and Forwarding (VRF) provides segmentation at layer 3, and works with Multiprotocol Label Switching (MPLS) for enterprise and WAN environments. When VRF is used without MPLS, it is referred to as VRF lite. For Voice Video systems, subnets, VLANs, and VRFs are used to separate media and signaling streams from all other traffic.'
  desc 'check', 'Verify the Voice Video Session Manager applies 802.1Q VLAN tags to signaling and media traffic or be in a private subnet..

If the Voice Video Session Manager does not apply 802.1Q VLAN tags to signaling and media traffic or be in a private subnet., this is a finding.'
  desc 'fix', 'Configure th Voice Video Session Manager to apply 802.1Q VLAN tags to signaling and media traffic or be in a private subnet.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7116r364772_chk'
  tag severity: 'medium'
  tag gid: 'V-206861'
  tag rid: 'SV-206861r508661_rule'
  tag stig_id: 'SRG-NET-000520-VVSM-00024'
  tag gtitle: 'SRG-NET-000520'
  tag fix_id: 'F-7116r364773_fix'
  tag 'documentable'
  tag legacy: ['V-62149', 'SV-76639']
  tag cci: ['CCI-002272', 'CCI-000366']
  tag nist: ['AC-16 (1)', 'CM-6 b']
end
