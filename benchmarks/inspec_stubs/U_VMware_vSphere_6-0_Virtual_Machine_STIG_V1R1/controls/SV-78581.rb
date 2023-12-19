control 'SV-78581' do
  title 'The system must disable VIX messages from the VM.'
  desc 'The VIX API is a library for writing scripts and programs to manipulate virtual machines. If you do not make use of custom VIX programming in your environment, then you should consider disabling certain features to reduce the potential for vulnerabilities. The ability to send messages from the VM to the host is one of these features. Note that disabling this feature does NOT adversely affect the functioning of VIX operations that originate outside the guest, so certain VMware and 3rd party solutions that rely upon this capability should continue to work. This is a deprecated interface.'
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the isolation.tools.vixMessage.disable value and verify it is set to true.

Note:  The VM must be powered off to view the advanced settings through the vSphere Client so it is recommended to view these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.vixMessage.disable

If the virtual machine advanced setting isolation.tools.vixMessage.disable does not exist or is not set to true, this is a finding.'
  desc 'fix', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the isolation.tools.vixMessage.disable value and set it to true.  If the setting does not exist click "Add Row" to add the setting to the virtual machine.

Note:  The VM must be powered off to configure the advanced settings through the vSphere Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

If the setting does not exist run:

Get-VM "VM Name" | New-AdvancedSetting -Name isolation.tools.vixMessage.disable -Value true

If the setting exists run:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.vixMessage.disable | Set-AdvancedSetting -Value true'
  impact 0.3
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64841r1_chk'
  tag severity: 'low'
  tag gid: 'V-64091'
  tag rid: 'SV-78581r1_rule'
  tag stig_id: 'VMCH-06-000027'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-70019r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
