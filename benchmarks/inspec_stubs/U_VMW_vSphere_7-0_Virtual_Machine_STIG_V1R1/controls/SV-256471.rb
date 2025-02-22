control 'SV-256471' do
  title 'All 3D features on the virtual machine (VM) must be disabled when not required.'
  desc 'For performance reasons, it is recommended that 3D acceleration be disabled on virtual machines that do not require 3D functionality (e.g., most server workloads or desktops not using 3D applications).'
  desc 'check', 'From the vSphere Client, select the Virtual Machine, right-click, and go to Edit Settings >> VM Options tab >> Advanced >> Configuration Parameters >> Edit Configuration.

Find the "mks.enable3d" value and verify it is set to "false".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name mks.enable3d

If the virtual machine advanced setting "mks.enable3d" does not exist or is not set to "false", this is a finding.

If a virtual machine requires 3D features, this is not a finding.'
  desc 'fix', 'From the vSphere Client, select the Virtual Machine, right-click, and go to Edit Settings >> VM Options tab >> Advanced >> Configuration Parameters >> Edit Configuration.

Find the "mks.enable3d" value and set it to "false".

Note: The VM must be powered off to modify the advanced settings through the vSphere Client. It is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. In this case, the modified settings will not take effect until a cold boot of the VM.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the provided commands as shown below.

If the setting does not exist, run:

Get-VM "VM Name" | New-AdvancedSetting -Name mks.enable3d -Value false

If the setting exists, run:

Get-VM "VM Name" | Get-AdvancedSetting -Name mks.enable3d | Set-AdvancedSetting -Value false'
  impact 0.3
  ref 'DPMS Target VMware vSphere 7.0 Virtual Machine'
  tag check_id: 'C-60146r886454_chk'
  tag severity: 'low'
  tag gid: 'V-256471'
  tag rid: 'SV-256471r886456_rule'
  tag stig_id: 'VMCH-70-000023'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60089r886455_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
