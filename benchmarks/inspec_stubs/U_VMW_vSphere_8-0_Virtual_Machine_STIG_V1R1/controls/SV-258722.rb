control 'SV-258722' do
  title 'Virtual machines (VMs) must remove unneeded floppy devices.'
  desc 'Ensure no device is connected to a virtual machine if it is not required. For example, floppy, serial, and parallel ports are rarely used for virtual machines in a data center environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc 'check', 'Floppy drives are no longer visible through the vSphere Client and must be done via the Application Programming Interface (API) or PowerCLI.

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM | Get-FloppyDrive | Select Parent, Name, ConnectionState

If a virtual machine has a floppy drive connected, this is a finding.'
  desc 'fix', 'Floppy drives are no longer visible through the vSphere Client and must be done via the Application Programming Interface (API) or PowerCLI.

The VM must be powered off to remove a floppy drive.

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-FloppyDrive | Remove-FloppyDrive'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62462r933225_chk'
  tag severity: 'medium'
  tag gid: 'V-258722'
  tag rid: 'SV-258722r933227_rule'
  tag stig_id: 'VMCH-80-000209'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62371r933226_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
