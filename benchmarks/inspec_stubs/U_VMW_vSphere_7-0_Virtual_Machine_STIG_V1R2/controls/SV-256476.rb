control 'SV-256476' do
  title 'DirectPath I/O must be disabled on the virtual machine (VM) when not required.'
  desc 'VMDirectPath I/O (PCI passthrough) enables direct assignment of hardware PCI functions to VMs. This gives the VM access to the PCI functions with minimal intervention from the ESXi host. This is a powerful feature for legitimate applications such as virtualized storage appliances, backup appliances, dedicated graphics, etc., but it also allows a potential attacker highly privileged access to underlying hardware and the PCI bus.'
  desc 'check', 'From the vSphere Client, select the Virtual Machine, right-click, and go to Edit Settings >> VM Options tab >> Advanced >> Configuration Parameters >> Edit Configuration.

Find any "pciPassthruX.present" value (where "X" is a count starting at 0) and verify it is set to "FALSE" or "".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name "pciPassthru*.present" | Select Entity, Name, Value

If the virtual machine advanced setting "pciPassthruX.present" is present, and the specific device returned is not approved, this is a finding.

If the virtual machine advanced setting "pciPassthruX.present" is not present, this is not a finding.'
  desc 'fix', %q(From the vSphere Client, select the Virtual Machine, right-click, and go to Edit Settings >> Virtual Hardware tab.

Find the unexpected PCI device returned from the check.

Hover the mouse over the device and click the circled "X" to remove the device. Click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name pciPassthruX.present | Remove-AdvancedSetting

Note: Change the "X"  value to match the specific setting in the organization's environment.)
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 Virtual Machine'
  tag check_id: 'C-60151r886469_chk'
  tag severity: 'medium'
  tag gid: 'V-256476'
  tag rid: 'SV-256476r886471_rule'
  tag stig_id: 'VMCH-70-000028'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60094r886470_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
