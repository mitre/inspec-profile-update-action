control 'SV-78541' do
  title 'The system must not use independent, non-persistent disks.'
  desc 'The security issue with nonpersistent disk mode is that successful attackers, with a simple shutdown or reboot, might undo or remove any traces that they were ever on the machine. To safeguard against this risk, production virtual machines should be set to use persistent disk mode; additionally, make sure that activity within the VM is logged remotely on a separate server, such as a syslog server or equivalent Windows-based event collector. Without a persistent record of activity on a VM, administrators might never know whether they have been attacked or hacked.'
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings.  Review the attached hard disks and verify they are not configured as independent nonpersistent disks.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-HardDisk | Select Parent, Name, Filename, DiskType, Persistence | FT -AutoSize

If the virtual machine has attached disks that are in independent nonpersistent mode, this is a finding.'
  desc 'fix', 'The target VM must be powered off prior to changing the hard disk mode.

From the vSphere Client select the Virtual Machine right click and go to Edit Settings.  Select the target hard disk and change the mode to persistent or uncheck Independent.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-HardDisk | Set-HardDisk -Persistence IndependentPersistent

or

Get-VM "VM Name" | Get-HardDisk | Set-HardDisk -Persistence Persistent'
  impact 0.7
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64801r1_chk'
  tag severity: 'high'
  tag gid: 'V-64051'
  tag rid: 'SV-78541r1_rule'
  tag stig_id: 'VMCH-06-000007'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69979r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
