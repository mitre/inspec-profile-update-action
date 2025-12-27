control 'SV-206808' do
  title 'The hardware Voice Video Endpoint must use a voice video VLAN, separate from all other VLANs.'
  desc 'Virtualized networking is used to separate voice video traffic from other types of traffic, such as data, management, and other special types. VLANs provide segmentation at layer 2. Virtual Routing and Forwarding (VRF) provides segmentation at layer 3, and works with Multiprotocol Label Switching (MPLS) for enterprise and WAN environments. When VRF is used without MPLS, it is referred to as VRF lite. For Voice Video systems, subnets, VLANs, and VRFs are used to separate media and signaling streams from all other traffic.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint, this check procedure is Not Applicable.

Verify the hardware Voice Video Endpoint uses a voice video VLAN separate from all other VLANs. For networks with both VoIP and videoconferencing, best practice is to have a separate voice VLAN and video VLAN.

If the hardware Voice Video Endpoint does not use a voice video VLAN separate from all other VLANs, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint to use a voice video VLAN separate from all other VLANs.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7064r363947_chk'
  tag severity: 'medium'
  tag gid: 'V-206808'
  tag rid: 'SV-206808r604140_rule'
  tag stig_id: 'SRG-NET-000520-VVEP-00011'
  tag gtitle: 'SRG-NET-000520'
  tag fix_id: 'F-7064r363948_fix'
  tag 'documentable'
  tag legacy: ['SV-81193', 'V-66703']
  tag cci: ['CCI-002272', 'CCI-000366']
  tag nist: ['AC-16 (1)', 'CM-6 b']
end
