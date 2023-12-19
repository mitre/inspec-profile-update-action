control 'SV-78535' do
  title 'The system must explicitly disable paste operations.'
  desc 'Copy and paste operations are disabled by default; however, by explicitly disabling this feature it will enable audit controls to check that this setting is correct. Copy, paste, drag and drop, or GUI copy/paste operations between the guest OS and the remote console could provide the means for an attacker to compromise the VM.'
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the isolation.tools.paste.disable value and verify it is set to true.

Note:  The VM must be powered off to view the advanced settings through the vSphere Client so it is recommended to view these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.paste.disable

If the virtual machine advanced setting isolation.tools.paste.disable does not exist or is not set to true, this is a finding.'
  desc 'fix', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the isolation.tools.paste.disable value and set it to true.  If the setting does not exist click "Add Row" to add the setting to the virtual machine.

Note:  The VM must be powered off to configure the advanced settings through the vSphere Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

If the setting does not exist run:

Get-VM "VM Name" | New-AdvancedSetting -Name isolation.tools.paste.disable -Value true

If the setting exists run:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.paste.disable | Set-AdvancedSetting -Value true'
  impact 0.3
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64795r1_chk'
  tag severity: 'low'
  tag gid: 'V-64045'
  tag rid: 'SV-78535r1_rule'
  tag stig_id: 'VMCH-06-000004'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69973r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
