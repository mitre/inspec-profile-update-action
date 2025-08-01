control 'SV-206862' do
  title 'The Voice Video Session Manager must use a voice or video VLAN, separate from all other VLANs.'
  desc 'When network elements do not dynamically reconfigure the data security attributes as data is created and combined, the possibility exist that security attributes will not correctly reflect the data with which they are associated. For the Voice Video Session Manager, the use of 802.1q tags on media and signaling, and the use of VLANs provides this layer of security. VLANs facilitate access and traffic control for voice video system components and enhanced QoS.

Virtualized networking is used to separate voice video traffic from other types of traffic, such as data, management, and other special types. VLANs provide segmentation at layer 2. Virtual Routing and Forwarding (VRF) provides segmentation at layer 3, and works with Multiprotocol Label Switching (MPLS) for enterprise and WAN environments. When VRF is used without MPLS, it is referred to as VRF lite. For Voice Video systems, subnets, VLANs, and VRFs are used to separate media and signaling streams from all other traffic.'
  desc 'check', 'Verify the Voice Video Session Manager uses a voice or video VLAN separate from all other VLANs.

If the Voice Video Session Manager uses a voice or video VLAN that is not separate from all other VLANs, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to use a voice or video VLAN, separate from all other VLANs.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7117r364775_chk'
  tag severity: 'medium'
  tag gid: 'V-206862'
  tag rid: 'SV-206862r508661_rule'
  tag stig_id: 'SRG-NET-000520-VVSM-00025'
  tag gtitle: 'SRG-NET-000520'
  tag fix_id: 'F-7117r364776_fix'
  tag 'documentable'
  tag legacy: ['V-62151', 'SV-76641']
  tag cci: ['CCI-000366', 'CCI-002272']
  tag nist: ['CM-6 b', 'AC-16 (1)']
end
