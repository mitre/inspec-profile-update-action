control 'SV-258721' do
  title 'Virtual machines (VMs) must not use independent, nonpersistent disks.'
  desc 'The security issue with nonpersistent disk mode is that successful attackers, with a simple shutdown or reboot, might undo or remove any traces they were ever on the machine. To safeguard against this risk, production virtual machines should be set to use persistent disk mode; additionally, ensure activity within the VM is logged remotely on a separate server, such as a syslog server or equivalent Windows-based event collector. Without a persistent record of activity on a VM, administrators might never know whether they have been attacked or hacked.

There can be valid use cases for these types of disks, such as with an application presentation solution where read-only disks are desired, and such cases should be identified and documented.'
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to "Edit Settings".

Review the attached hard disks and verify they are not configured as independent nonpersistent disks.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-HardDisk | Select Parent, Name, Filename, DiskType, Persistence | FT -AutoSize

If the virtual machine has attached disks that are in independent nonpersistent mode and are not documented, this is a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to "Edit Settings".

Select the target hard disk and change the mode to persistent or uncheck Independent.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run one of the following commands:

Get-VM "VM Name" | Get-HardDisk | Set-HardDisk -Persistence IndependentPersistent

or

Get-VM "VM Name" | Get-HardDisk | Set-HardDisk -Persistence Persistent'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62461r933222_chk'
  tag severity: 'medium'
  tag gid: 'V-258721'
  tag rid: 'SV-258721r933224_rule'
  tag stig_id: 'VMCH-80-000208'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62370r933223_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
