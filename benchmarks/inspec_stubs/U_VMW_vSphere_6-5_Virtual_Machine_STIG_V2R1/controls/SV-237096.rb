control 'SV-237096' do
  title 'The virtual machine must not be able to obtain host information from the hypervisor.'
  desc 'If enabled, a VM can obtain detailed information about the physical host. The default value for the parameter is FALSE. This setting should not be TRUE unless a particular VM requires this information for performance monitoring. An adversary potentially can use this information to inform further attacks on the host.'
  desc 'check', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Verify the tools.guestlib.enableHostInfo value is set to false.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo

If the virtual machine advanced setting tools.guestlib.enableHostInfo does not exist or is not set to false, this is a finding.'
  desc 'fix', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Find the tools.guestlib.enableHostInfo value and set it to false. If the setting does not exist, add the Name and Value setting at the bottom of screen.

Note: The VM must be powered off to configure the advanced settings through the vSphere Web Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

If the setting does not exist, run:

Get-VM "VM Name" | New-AdvancedSetting -Name tools.guestlib.enableHostInfo -Value false

If the setting exists, run:

Get-VM "VM Name" | Get-AdvancedSetting -Name tools.guestlib.enableHostInfo | Set-AdvancedSetting -Value false'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 Virtual Machine'
  tag check_id: 'C-40315r640123_chk'
  tag severity: 'medium'
  tag gid: 'V-237096'
  tag rid: 'SV-237096r640125_rule'
  tag stig_id: 'VMCH-65-000039'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-40278r640124_fix'
  tag 'documentable'
  tag legacy: ['SV-104461', 'V-94631']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
