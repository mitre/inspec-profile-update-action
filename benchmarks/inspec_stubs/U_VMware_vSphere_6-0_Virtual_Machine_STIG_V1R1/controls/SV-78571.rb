control 'SV-78571' do
  title 'The unexposed feature keyword isolation.tools.unity.taskbar.disable must be set.'
  desc 'Some virtual machine advanced settings parameters do not apply on vSphere because VMware virtual machines work on both vSphere and hosted virtualization platforms such as Workstation and Fusion. Explicitly disabling these features reduces the potential for vulnerabilities because it reduces the number of ways in which a guest can affect the host.'
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the isolation.tools.unity.taskbar.disable value and verify it is set to true.

Note:  The VM must be powered off to view the advanced settings through the vSphere Client so it is recommended to view these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.unity.taskbar.disable

If the virtual machine advanced setting isolation.tools.unity.taskbar.disable does not exist or is not set to true, this is a finding.'
  desc 'fix', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the isolation.tools.unity.taskbar.disable value and set it to true.  If the setting does not exist click "Add Row" to add the setting to the virtual machine.

Note:  The VM must be powered off to configure the advanced settings through the vSphere Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

If the setting does not exist run:

Get-VM "VM Name" | New-AdvancedSetting -Name isolation.tools.unity.taskbar.disable -Value true

If the setting exists run:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.unity.taskbar.disable | Set-AdvancedSetting -Value true'
  impact 0.3
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64831r1_chk'
  tag severity: 'low'
  tag gid: 'V-64081'
  tag rid: 'SV-78571r1_rule'
  tag stig_id: 'VMCH-06-000022'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-70009r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
