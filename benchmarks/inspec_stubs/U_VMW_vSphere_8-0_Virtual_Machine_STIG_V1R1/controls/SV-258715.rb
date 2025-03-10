control 'SV-258715' do
  title 'Virtual machines (VMs) must disable 3D features when not required.'
  desc 'For performance reasons, it is recommended that 3D acceleration be disabled on virtual machines that do not require 3D functionality (e.g., most server workloads or desktops not using 3D applications).'
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings.

Expand the "Video card" and verify the "Enable 3D Support" checkbox is unchecked.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name mks.enable3d

If the virtual machine advanced setting "mks.enable3d" exists and is not set to "false", this is a finding.

If the virtual machine advanced setting "mks.enable3d" does not exist, this is not a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings.

Expand the "Video card" and uncheck the "Enable 3D Support" checkbox.

Click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name mks.enable3d | Set-AdvancedSetting -Value "false"

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.'
  impact 0.3
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62455r933204_chk'
  tag severity: 'low'
  tag gid: 'V-258715'
  tag rid: 'SV-258715r933206_rule'
  tag stig_id: 'VMCH-80-000202'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62364r933205_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
