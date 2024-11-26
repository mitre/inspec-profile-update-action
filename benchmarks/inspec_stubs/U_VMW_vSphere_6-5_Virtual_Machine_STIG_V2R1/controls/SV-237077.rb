control 'SV-237077' do
  title 'The unexposed feature keyword isolation.ghi.host.shellAction.disable must be set on the virtual machine.'
  desc 'Some virtual machine advanced settings parameters do not apply on vSphere because VMware virtual machines work on both vSphere and hosted virtualization platforms such as Workstation and Fusion. Explicitly disabling these features reduces the potential for vulnerabilities because it reduces the number of ways in which a guest can affect the host.'
  desc 'check', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Verify the isolation.ghi.host.shellAction.disable value is set to true.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.ghi.host.shellAction.disable

If the virtual machine advanced setting isolation.ghi.host.shellAction.disable does not exist or is not set to true, this is a finding.'
  desc 'fix', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Find the isolation.ghi.host.shellAction.disable value and set it to true. If the setting does not exist, add the Name and Value setting at the bottom of screen.

Note: The VM must be powered off to configure the advanced settings through the vSphere Web Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

If the setting does not exist, run:

Get-VM "VM Name" | New-AdvancedSetting -Name isolation.ghi.host.shellAction.disable -Value true

If the setting exists, run:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.ghi.host.shellAction.disable | Set-AdvancedSetting -Value true'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.5 Virtual Machine'
  tag check_id: 'C-40296r640066_chk'
  tag severity: 'low'
  tag gid: 'V-237077'
  tag rid: 'SV-237077r640068_rule'
  tag stig_id: 'VMCH-65-000015'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-40259r640067_fix'
  tag 'documentable'
  tag legacy: ['SV-104423', 'V-94593']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
