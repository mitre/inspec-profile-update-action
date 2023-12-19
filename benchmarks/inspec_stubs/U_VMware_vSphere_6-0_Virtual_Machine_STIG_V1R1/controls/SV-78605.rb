control 'SV-78605' do
  title 'The system must not send host information to guests.'
  desc 'If enabled, a VM can obtain detailed information about the physical host. The default value for the parameter is FALSE. This setting should not be TRUE unless a particular VM requires this information for performance monitoring. An adversary potentially can use this information to inform further attacks on the host.'
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the tools.guestlib.enableHostInfo value and verify it is set to false.

Note:  The VM must be powered off to view the advanced settings through the vSphere Client so it is recommended to view these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo

If the virtual machine advanced setting tools.guestlib.enableHostInfo does not exist or is not set to false, this is a finding.'
  desc 'fix', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the tools.guestlib.enableHostInfo value and set it to false.  If the setting does not exist click "Add Row" to add the setting to the virtual machine.

Note:  The VM must be powered off to configure the advanced settings through the vSphere Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

If the setting does not exist run:

Get-VM "VM Name" | New-AdvancedSetting -Name tools.guestlib.enableHostInfo -Value false

If the setting exists run:

Get-VM "VM Name" | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo | Set-AdvancedSetting -Value false'
  impact 0.5
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64865r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64115'
  tag rid: 'SV-78605r1_rule'
  tag stig_id: 'VMCH-06-000039'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-70043r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
