control 'SV-206752' do
  title 'The hardware Voice Video Endpoint PC port must maintain VLAN separation from the voice video VLAN, or be disabled.'
  desc 'Virtualized networking is used to separate voice video traffic from other types of traffic, such as data, management, and other special types. VLANs provide segmentation at layer 2. Virtual Routing and Forwarding (VRF) provides segmentation at layer 3, and works with Multiprotocol Label Switching (MPLS) for enterprise and WAN environments. When VRF is used without MPLS, it is referred to as VRF lite. For Voice Video systems, subnets, VLANs, and VRFs are used to separate media and signaling streams from all other traffic.'
  desc 'check', 'If the Voice Video Endpoint is not a hardware endpoint, this check procedure is Not Applicable.

Verify the hardware Voice Video Endpoint PC port maintains VLAN separation from the voice video VLAN or is disabled. For networks with both VoIP and videoconferencing, best practice is to have a separate voice VLAN and video VLAN.

If the hardware Voice Video Endpoint PC port is disabled, this is not a finding. If the hardware Voice Video Endpoint PC port does not maintain VLAN separation from the voice video VLAN, this is a finding.'
  desc 'fix', 'Configure the hardware Voice Video Endpoint PC port to maintain VLAN separation from the voice video VLAN or be disabled.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7008r363779_chk'
  tag severity: 'medium'
  tag gid: 'V-206752'
  tag rid: 'SV-206752r604140_rule'
  tag stig_id: 'SRG-NET-000057-VVEP-00012'
  tag gtitle: 'SRG-NET-000057'
  tag fix_id: 'F-7008r363780_fix'
  tag 'documentable'
  tag legacy: ['SV-81195', 'V-66705']
  tag cci: ['CCI-000366', 'CCI-001424']
  tag nist: ['CM-6 b', 'AC-16 (1)']
end
