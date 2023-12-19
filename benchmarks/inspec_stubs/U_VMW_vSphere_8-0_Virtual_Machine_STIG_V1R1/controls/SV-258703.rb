control 'SV-258703' do
  title 'Virtual machines (VMs) must have copy operations disabled.'
  desc 'Copy and paste operations are disabled by default; however, explicitly disabling this feature will enable audit controls to verify this setting is correct. Copy, paste, drag and drop, or GUI copy/paste operations between the guest operating system and the remote console could provide the means for an attacker to compromise the VM.'
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Verify the "isolation.tools.copy.disable" value is set to "true".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.copy.disable

If the virtual machine advanced setting "isolation.tools.copy.disable" is not set to "true", this is a finding.

If the virtual machine advanced setting "isolation.tools.copy.disable" does not exist, this is not a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Find the "isolation.tools.copy.disable" value and set it to "true".

If the setting does not exist no action is needed. 

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.copy.disable | Set-AdvancedSetting -Value true

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.'
  impact 0.3
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62443r933168_chk'
  tag severity: 'low'
  tag gid: 'V-258703'
  tag rid: 'SV-258703r933170_rule'
  tag stig_id: 'VMCH-80-000189'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62352r933169_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
