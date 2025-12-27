control 'SV-237072' do
  title 'HGFS file transfers must be disabled on the virtual machine.'
  desc "Setting isolation.tools.hgfsServerSet.disable to true disables registration of the guest's HGFS server with the host. APIs that use HGFS to transfer files to and from the guest operating system, such as some VIX commands, will not function. An attacker could potentially use this to transfer files inside the guest OS."
  desc 'check', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Verify the isolation.tools.hgfsServerSet.disable value is set to true.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable

If the virtual machine advanced setting isolation.tools.hgfsServerSet.disable does not exist or is not set to true, this is a finding.'
  desc 'fix', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings >> VM Options >> Advanced >> Configuration Parameters >> Edit Configuration. Find the isolation.tools.hgfsServerSet.disable value and set it to true. If the setting does not exist, add the Name and Value setting at the bottom of screen.

Note: The VM must be powered off to configure the advanced settings through the vSphere Web Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

If the setting does not exist, run:

Get-VM "VM Name" | New-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable -Value true

If the setting exists, run:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable | Set-AdvancedSetting -Value true'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 Virtual Machine'
  tag check_id: 'C-40291r640051_chk'
  tag severity: 'medium'
  tag gid: 'V-237072'
  tag rid: 'SV-237072r640053_rule'
  tag stig_id: 'VMCH-65-000008'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-40254r640052_fix'
  tag 'documentable'
  tag legacy: ['SV-104407', 'V-94577']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
