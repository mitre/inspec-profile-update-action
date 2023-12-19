control 'SV-258709' do
  title 'Virtual machines (VMs) must limit informational messages from the virtual machine to the VMX file.'
  desc 'The configuration file containing these name-value pairs is limited to a size of 1MB. If not limited, VMware tools in the guest operating system are capable of sending a large and continuous data stream to the host. This 1MB capacity should be sufficient for most cases, but this value can change if necessary.

The value can be increased if large amounts of custom information are being stored in the configuration file. The default limit is 1MB.'
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Verify the "tools.setinfo.sizeLimit" value is set to "1048576".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name tools.setinfo.sizeLimit

If the virtual machine advanced setting "tools.setinfo.sizeLimit" is not set to "1048576", this is a finding.

If the virtual machine advanced setting "tools.setinfo.sizeLimit" does not exist, this is not a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Find the "tools.setinfo.sizeLimit" value and set it to "1048576".

If the setting does not exist no action is needed. 

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name tools.setinfo.sizeLimit | Set-AdvancedSetting -Value 1048576

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.'
  impact 0.3
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62449r933186_chk'
  tag severity: 'low'
  tag gid: 'V-258709'
  tag rid: 'SV-258709r933188_rule'
  tag stig_id: 'VMCH-80-000196'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62358r933187_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
