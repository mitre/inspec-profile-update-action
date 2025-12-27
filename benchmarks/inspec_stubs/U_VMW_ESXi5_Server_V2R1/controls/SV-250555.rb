control 'SV-250555' do
  title 'The system must ensure that the virtual switch Forged Transmits policy is set to reject.'
  desc 'If the virtual machine operating system changes the MAC address, the operating system can send frames with an impersonated source MAC address at any time. This allows an operating system to stage malicious attacks on the devices in a network by impersonating a network adaptor authorized by the receiving network. Forged transmissions should be set to accept by default. This means the virtual switch does not compare the source and effective MAC addresses. To protect against MAC address impersonation, all virtual switches should have forged transmissions set to reject.'
  desc 'check', %q(The "Forged Transmits" parameter must be set to "Reject" on all vSwitches.

From the vSphere Client/vCenter as administrator, verify by using the vSphere Client to connect to the vCenter Server and as administrator: 
1. Go to "Home > Inventory > Hosts and clusters". 
2. Select each ESXi host with active virtual switches connected to active VM's requiring securing. 
3. Go to tab "Configuration > Network > vSwitch(?) > Properties > Ports > vSwitch > Default Policies > Security" 
4. "Forged Transmits" = "Reject"

If the "Forged Transmits" parameter is not set to "Reject" on all vSwitches, this is a finding.)
  desc 'fix', %q(The "Forged Transmits" parameter must be set to "Reject" on all vSwitches.

From the vSphere Client/vCenter as administrator, using the vSphere Client to connect to the vCenter Server and as administrator: 1. Go to "Home > Inventory > Hosts and clusters". 2. Select each ESXi host with active virtual switches connected to active VM's requiring securing. 3. Go to tab "Configuration > Network > vSwitch(?) > Properties > Ports > vSwitch > Default Policies > Security" 4. Set "Forged Transmits" = "Reject".)
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-53990r798662_chk'
  tag severity: 'medium'
  tag gid: 'V-250555'
  tag rid: 'SV-250555r798664_rule'
  tag stig_id: 'ESXI5-VMNET-000013'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-53944r798663_fix'
  tag 'documentable'
  tag legacy: ['V-39370', 'SV-51228']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
