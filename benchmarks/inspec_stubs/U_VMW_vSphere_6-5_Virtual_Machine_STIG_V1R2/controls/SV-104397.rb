control 'SV-104397' do
  title 'GUI functionality for copy/paste operations must be disabled on the virtual machine.'
  desc 'Copy and paste operations are disabled by default; however, by explicitly disabling this feature it will enable audit controls to check that this setting is correct. Copy, paste, drag and drop, or GUI copy/paste operations between the guest OS and the remote console could provide the means for an attacker to compromise the VM.'
  desc 'check', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Verify the isolation.tools.setGUIOptions.enable value is set to false.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.setGUIOptions.enable

If the virtual machine advanced setting isolation.tools.setGUIOptions.enable does not exist or is not set to false, this is a finding.'
  desc 'fix', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Find the isolation.tools.setGUIOptions.enable value and set it to false. If the setting does not exist, add the Name and Value setting at the bottom of screen.

Note: The VM must be powered off to configure the advanced settings through the vSphere Web Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

If the setting does not exist, run:

Get-VM "VM Name" | New-AdvancedSetting -Name isolation.tools.setGUIOptions.enable -Value false

If the setting exists, run:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.setGUIOptions.enable | Set-AdvancedSetting -Value false'
  impact 0.3
  ref 'DPMS Target VMWare Virtual Machine 6.5'
  tag check_id: 'C-93755r1_chk'
  tag severity: 'low'
  tag gid: 'V-94567'
  tag rid: 'SV-104397r1_rule'
  tag stig_id: 'VMCH-65-000003'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-100683r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
