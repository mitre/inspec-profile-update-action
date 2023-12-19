control 'SV-258714' do
  title 'Virtual machines (VMs) must be configured to lock when the last console connection is closed.'
  desc 'When accessing the VM console, the guest operating system must be locked when the last console user disconnects, limiting the possibility of session hijacking. This setting only applies to Windows-based VMs with VMware tools installed.'
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> VMware Remote Console Options.

Verify the option "Lock the guest operating system when the last remote user disconnects" is checked.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name tools.guest.desktop.autolock

If the virtual machine advanced setting "tools.guest.desktop.autolock" is not set to "true", this is a finding.

If the virtual machine advanced setting "tools.guest.desktop.autolock" does not exist, this is not a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> VM Options >> VMware Remote Console Options.

Check the box next to "Lock the guest operating system when the last remote user disconnects". Click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name tools.guest.desktop.autolock | Set-AdvancedSetting -Value true'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62454r933201_chk'
  tag severity: 'medium'
  tag gid: 'V-258714'
  tag rid: 'SV-258714r933203_rule'
  tag stig_id: 'VMCH-80-000201'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62363r933202_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
