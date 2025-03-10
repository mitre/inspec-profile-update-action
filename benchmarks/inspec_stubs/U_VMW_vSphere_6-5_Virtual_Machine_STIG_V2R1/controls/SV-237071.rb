control 'SV-237071' do
  title 'Independent, non-persistent disks must be not be used on the virtual machine.'
  desc 'The security issue with nonpersistent disk mode is that successful attackers, with a simple shutdown or reboot, might undo or remove any traces that they were ever on the machine. To safeguard against this risk, production virtual machines should be set to use persistent disk mode; additionally, make sure that activity within the VM is logged remotely on a separate server, such as a syslog server or equivalent Windows-based event collector. Without a persistent record of activity on a VM, administrators might never know whether they have been attacked or hacked.  

There can be valid use cases for these types of disks such as with an application presentation solution where read only disks are desired and such cases should be identified and documented.'
  desc 'check', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings. Review the attached hard disks and verify they are not configured as independent nonpersistent disks.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-HardDisk | Select Parent, Name, Filename, DiskType, Persistence | FT -AutoSize

If the virtual machine has attached disks that are in independent nonpersistent mode and are not documented, this is a finding.'
  desc 'fix', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings. Select the target hard disk and change the mode to persistent or uncheck Independent.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-HardDisk | Set-HardDisk -Persistence IndependentPersistent

or

Get-VM "VM Name" | Get-HardDisk | Set-HardDisk -Persistence Persistent'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 Virtual Machine'
  tag check_id: 'C-40290r640048_chk'
  tag severity: 'medium'
  tag gid: 'V-237071'
  tag rid: 'SV-237071r640050_rule'
  tag stig_id: 'VMCH-65-000007'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-40253r640049_fix'
  tag 'documentable'
  tag legacy: ['SV-104405', 'V-94575']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
