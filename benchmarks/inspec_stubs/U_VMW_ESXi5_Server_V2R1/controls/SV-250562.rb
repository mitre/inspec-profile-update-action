control 'SV-250562' do
  title 'The system must ensure there are no unused ports on a distributed virtual port group.'
  desc 'The number of ports available on a dvSwitch distributed port group must be adjusted to exactly match the number of virtual machine vNICs that need to be assigned to that dvPortgroup. Limiting the number of ports to just what is needed also limits the accidental or malicious potential to move a virtual machine to an unauthorized network.  This is especially relevant if the management network is on a dvPortgroup, because it could help prevent putting a rogue virtual machine on this network.'
  desc 'check', 'If a vNetwork Distributed Switch (vDS) is not configured, this is not applicable.

As administrator, find all dvSwitches from the vSphere Client/vCenter, Home >> Inventory >> Networking view. For any dvSwitches with dvPortgroups, verify the settings for that dvPortgroup. Compare the number of ports in that port group to the number of vNICs connecting to that port group. The number of ports must match, or approximate to the nearest number of menu selectable ports, the number of vNICs residing in that port group.

If the number of ports in the port group do not match (or approximate to the nearest number of menu selectable ports) the number of VM NICs connecting to that port group, this is a finding.'
  desc 'fix', 'As administrator, find all dvSwitches from the vSphere Client/vCenter:
Home >> Inventory >> Networking view.

For dvSwitches with dvPortgroups, edit the settings for that dvPortgroup. Limit (match or approximate) the number of ports in that port group to the number of vNICs residing in that port group.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53997r798683_chk'
  tag severity: 'low'
  tag gid: 'V-250562'
  tag rid: 'SV-250562r798685_rule'
  tag stig_id: 'ESXI5-VMNET-000020'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53951r798684_fix'
  tag 'documentable'
  tag legacy: ['SV-51235', 'V-39377']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
