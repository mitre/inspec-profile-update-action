control 'SV-78583' do
  title 'The system must disconnect unauthorized floppy devices.'
  desc 'Ensure that no device is connected to a virtual machine if it is not required. For example, floppy, serial and parallel ports are rarely used for virtual machines in a datacenter environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings.  Review the VMs hardware and verify no floppy devices exist.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM | Get-FloppyDrive | Select Parent, Name, ConnectionState

If a virtual machine has a floppy drive present, this is a finding.'
  desc 'fix', 'The VM must be powered off in order to remove a floppy drive.

From the vSphere Client select the Virtual Machine right click and go to Edit Settings.  Select the floppy drive and click remove then OK.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-FloppyDrive | Remove-FloppyDrive'
  impact 0.5
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64843r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64093'
  tag rid: 'SV-78583r1_rule'
  tag stig_id: 'VMCH-06-000028'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-70021r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
