control 'SV-78595' do
  title 'The system must disable console access through the VNC protocol.'
  desc 'The VM console enables you to connect to the console of a virtual machine, in effect seeing what a monitor on a physical server would show. This console is also available via the Virtual Network Computing (VNC) protocol and should be disabled.'
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the RemoteDisplay.vnc.enabled value and verify it is set to false.

Note:  The VM must be powered off to view the advanced settings through the vSphere Client so it is recommended to view these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name RemoteDisplay.vnc.enabled

If the virtual machine advanced setting RemoteDisplay.vnc.enabled does not exist or is not set to false, this is a finding.'
  desc 'fix', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the RemoteDisplay.vnc.enabled value and set it to false.  If the setting does not exist click "Add Row" to add the setting to the virtual machine.

Note:  The VM must be powered off to configure the advanced settings through the vSphere Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

If the setting does not exist run:

Get-VM "VM Name" | New-AdvancedSetting -Name RemoteDisplay.vnc.enabled -Value false

If the setting exists run:

Get-VM "VM Name" | Get-AdvancedSetting -Name RemoteDisplay.vnc.enabled | Set-AdvancedSetting -Value false'
  impact 0.5
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64855r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64105'
  tag rid: 'SV-78595r1_rule'
  tag stig_id: 'VMCH-06-000034'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-70033r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
