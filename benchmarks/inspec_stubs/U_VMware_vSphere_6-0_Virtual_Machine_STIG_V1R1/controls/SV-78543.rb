control 'SV-78543' do
  title 'The system must disable HGFS file transfers.'
  desc "Setting isolation.tools.hgfsServerSet.disable to true disables registration of the guest's HGFS server with the host. APIs that use HGFS to transfer files to and from the guest operating system, such as some VIX commands, will not function. An attacker could potentially use this to transfer files inside the guest OS."
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the isolation.tools.hgfsServerSet.disable value and verify it is set to true.

Note:  The VM must be powered off to view the advanced settings through the vSphere Client so it is recommended to view these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable

If the virtual machine advanced setting isolation.tools.hgfsServerSet.disable does not exist or is not set to true, this is a finding.'
  desc 'fix', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the isolation.tools.hgfsServerSet.disable value and set it to true.  If the setting does not exist click "Add Row" to add the setting to the virtual machine.

Note:  The VM must be powered off to configure the advanced settings through the vSphere Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

If the setting does not exist run:

Get-VM "VM Name" | New-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable -Value true

If the setting exists run:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.hgfsServerSet.disable | Set-AdvancedSetting -Value true'
  impact 0.5
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64803r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64053'
  tag rid: 'SV-78543r1_rule'
  tag stig_id: 'VMCH-06-000008'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69981r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
