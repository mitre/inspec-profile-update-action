control 'SRG-NET-000018-VVEP-00107_rule' do
  title 'The Unified Communications Endpoint must be configured to use a voice video VLAN, separate from all other VLANs.'
  desc 'Virtualized networking is used to separate voice video traffic from other types of traffic, such as data, management, and other special types. VLANs provide segmentation at layer 2. Virtual Routing and Forwarding (VRF) provides segmentation at layer 3 and works with Multiprotocol Label Switching (MPLS) for enterprise and WAN environments. When VRF is used without MPLS, it is referred to as VRF lite. For Voice Video systems, subnets, VLANs, and VRFs are used to separate media and signaling streams from all other traffic.'
  desc 'check', 'Verify the Unified Communications Endpoint is configured to use a voice video VLAN separate from all other VLANs. For networks with both VoIP and videoconferencing, best practice is to have a separate voice VLAN and video VLAN.

If the Unified Communications Endpoint does not use a voice video VLAN separate from all other VLANs, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to use a voice video VLAN separate from all other VLANs.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000018-VVEP-00107_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000018-VVEP-00107'
  tag rid: 'SRG-NET-000018-VVEP-00107_rule'
  tag stig_id: 'SRG-NET-000018-VVEP-00107'
  tag gtitle: 'SRG-NET-000018-VVEP-00107'
  tag fix_id: 'F-SRG-NET-000018-VVEP-00107_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
