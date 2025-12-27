control 'SV-78599' do
  title 'The system must limit informational messages from the VM to the VMX file.'
  desc 'The configuration file containing these name-value pairs is limited to a size of 1MB. If not limited, VMware tools in the guest OS are capable of sending a large and continuous data stream to the host. This 1MB capacity should be sufficient for most cases, but this value can change if necessary. The value can be increased if large amounts of custom information are being stored in the configuration file. The default limit is 1MB.'
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the tools.setinfo.sizeLimit value and verify it is set to 1048576.

Note:  The VM must be powered off to view the advanced settings through the vSphere Client so it is recommended to view these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name tools.setinfo.sizeLimit

If the virtual machine advanced setting tools.setinfo.sizeLimit does not exist or is not set to 1048576, this is a finding.'
  desc 'fix', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the tools.setinfo.sizeLimit value and set it to 1048576.  If the setting does not exist click "Add Row" to add the setting to the virtual machine.

Note:  The VM must be powered off to configure the advanced settings through the vSphere Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

If the setting does not exist run:

Get-VM "VM Name" | New-AdvancedSetting -Name tools.setinfo.sizeLimit -Value 1048576

If the setting exists run:

Get-VM "VM Name" | Get-AdvancedSetting -Name tools.setinfo.sizeLimit | Set-AdvancedSetting -Value 1048576'
  impact 0.3
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64859r1_chk'
  tag severity: 'low'
  tag gid: 'V-64109'
  tag rid: 'SV-78599r1_rule'
  tag stig_id: 'VMCH-06-000036'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-70037r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
