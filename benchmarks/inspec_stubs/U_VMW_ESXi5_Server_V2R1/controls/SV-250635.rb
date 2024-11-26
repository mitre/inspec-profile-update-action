control 'SV-250635' do
  title 'vSphere management traffic must be on a restricted network.'
  desc 'The vSphere management network provides access to the vSphere management interface on each component. Services running on the management interface provide an opportunity for an attacker to gain privileged access to the systems. Any remote attack most likely would begin with gaining entry to this network.'
  desc 'check', "The ESXi server's vSphere management port group should be in a dedicated VLAN on a common vSwitch. The vSwitch can be shared with production (virtual machine) traffic, as long as the vSphere management port group's VLAN is not used by production virtual machines. Check that the network segment is not routed, except possibly to networks where other management-related entities are found. Production virtual machine traffic must not be routed to this network. As root (or using a different administrator Active Directory account), from the vSphere Client/vCenter, select the host; select the Configuration tab; then select Hardware/Networking. Select switch Properties for the Management Network NIC, and in the Ports tab, verify that the Management Port Group list does not include any production virtual machine traffic.

If the network segment is routed, except to networks where other management-related entities are located, this is a finding.

If production virtual machine traffic is routed to this network, this is a finding.

Note that this check refers to an entity outside the scope of the ESXi server system."
  desc 'fix', "The vSphere management port group should be in a dedicated VLAN on a common vSwitch. The vSwitch can be shared with production (virtual machine) traffic, as long as the vSphere management port group's VLAN is not used by production virtual machines. As root (or using a different administrator Active Directory account), from the vSphere Client/vCenter, select the host; select the Configuration tab; then select Hardware/Networking. Select switch Properties for the Management Network NIC, and select the Ports tab. If any virtual machine traffic is found in the port list, create another vSwitch and migrate either the Management Port group or virtual machine traffic to a different vSwitch. Under the Configuration tab, select the Add Networking wizard, select either the Virtual Machine or VMkernel radio button, click Next and follow the directions for selecting the remaining switch type and connection settings based on the local system's hardware."
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54070r798902_chk'
  tag severity: 'medium'
  tag gid: 'V-250635'
  tag rid: 'SV-250635r798904_rule'
  tag stig_id: 'SRG-OS-000132-ESXI5'
  tag gtitle: 'SRG-OS-000132-VMM-000650'
  tag fix_id: 'F-54024r798903_fix'
  tag 'documentable'
  tag legacy: ['V-39393', 'SV-51251']
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
