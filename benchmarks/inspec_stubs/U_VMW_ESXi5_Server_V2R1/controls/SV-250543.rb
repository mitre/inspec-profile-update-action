control 'SV-250543' do
  title 'All dvPortgroup VLAN IDs must be fully documented.'
  desc 'If using VLAN tagging on a dvPortgroup, tags must correspond to the IDs on external VLAN-aware upstream switches if any. If VLAN IDs are not tracked completely, mistaken re-use of IDs could allow for traffic to be allowed between inappropriate physical and virtual machines. Similarly, wrong or missing VLAN IDs may lead to traffic not passing between appropriate physical and virtual machines.'
  desc 'check', 'If a vNetwork Distributed Switch (vDS) is not configured, this is not applicable.

From the vSphere Client log into vCS. Home >> Inventory >> Networking. Select dvSwitch and dvPortgroup and Edit Settings >> Policies >> VLAN >> VLAN ID. The dvPortGroup VLAN tags must be documented to match the IDs on external VLAN-aware upstream switches. Verify that VLAN IDs are documented and matched in an (organization-specific) tracking system. 

If the VLAN tagging on a dvPortgroup does not correspond to the IDs on external VLAN-aware upstream switches, this is a finding.'
  desc 'fix', 'From the vSphere Client log into vCS. Home >> Inventory >> Networking. Select dvSwitch and dvPortgroup and Edit Settings >> Policies >> VLAN >> VLAN ID. Record all VLAN IDs in an organization defined tracking system.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53978r798626_chk'
  tag severity: 'low'
  tag gid: 'V-250543'
  tag rid: 'SV-250543r798628_rule'
  tag stig_id: 'ESXI5-VMNET-000001'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53932r798627_fix'
  tag 'documentable'
  tag legacy: ['V-39356', 'SV-51214']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
