control 'SV-239346' do
  title 'Informational messages from the virtual machine to the VMX file must be limited on the virtual machine.'
  desc 'The configuration file containing these name-value pairs is limited to a size of 1MB. If not limited, VMware tools in the guest OS are capable of sending a large and continuous data stream to the host. This 1MB capacity should be sufficient for most cases, but this value can change if necessary. The value can be increased if large amounts of custom information are being stored in the configuration file. The default limit is 1MB.'
  desc 'check', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Verify the tools.setinfo.sizeLimit value is set to 1048576.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name tools.setinfo.sizeLimit

If the virtual machine advanced setting tools.setinfo.sizeLimit does not exist or is not set to 1048576, this is a finding.'
  desc 'fix', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Find the tools.setinfo.sizeLimit value and set it to 1048576. If the setting does not exist, add the Name and Value setting at the bottom of screen.

Note: The VM must be powered off to configure the advanced settings through the vSphere Web Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

If the setting does not exist, run:

Get-VM "VM Name" | New-AdvancedSetting -Name tools.setinfo.sizeLimit -Value 1048576

If the setting exists, run:

Get-VM "VM Name" | Get-AdvancedSetting -Name tools.setinfo.sizeLimit | Set-AdvancedSetting -Value 1048576'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.7 Virtual Machine'
  tag check_id: 'C-42579r679585_chk'
  tag severity: 'low'
  tag gid: 'V-239346'
  tag rid: 'SV-239346r679587_rule'
  tag stig_id: 'VMCH-67-000015'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-42538r679586_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
