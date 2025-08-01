control 'SRG-NET-000018-VVEP-00101_rule' do
  title 'The Unified Communications Endpoint PC port must be configured to maintain VLAN separation from the voice video VLAN, or be disabled.'
  desc 'Virtualized networking is used to separate voice video traffic from other types of traffic, such as data, management, and other special types. VLANs provide segmentation at layer 2. Virtual Routing and Forwarding (VRF) provides segmentation at layer 3 and works with Multiprotocol Label Switching (MPLS) for enterprise and WAN environments. When VRF is used without MPLS, it is referred to as VRF lite. For Voice Video systems, subnets, VLANs, and VRFs are used to separate media and signaling streams from all other traffic.'
  desc 'check', 'Verify the  Unified Communications Endpoint PC port is configured to maintain VLAN separation from the voice video VLAN or is disabled. For networks with both VoIP and videoconferencing, best practice is to have a separate voice VLAN and video VLAN.

If the  Unified Communications Endpoint PC port is disabled, this is not a finding. If the  Unified Communications Endpoint PC port does not maintain VLAN separation from the voice video VLAN, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint PC port to maintain VLAN separation from the voice video VLAN or be disabled.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000018-VVEP-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000018-VVEP-00101'
  tag rid: 'SRG-NET-000018-VVEP-00101_rule'
  tag stig_id: 'SRG-NET-000018-VVEP-00101'
  tag gtitle: 'SRG-NET-000018-VVEP-00101'
  tag fix_id: 'F-SRG-NET-000018-VVEP-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
