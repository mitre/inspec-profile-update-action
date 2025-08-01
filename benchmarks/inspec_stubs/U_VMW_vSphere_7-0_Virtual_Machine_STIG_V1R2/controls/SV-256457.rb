control 'SV-256457' do
  title 'Unauthorized floppy devices must be disconnected on the virtual machine (VM).'
  desc 'Ensure no device is connected to a virtual machine if it is not required. For example, floppy, serial, and parallel ports are rarely used for virtual machines in a data center environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc 'check', 'Floppy drives are no longer visible through the vSphere Client and must be done via the Application Programming Interface (API) or PowerCLI.

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM | Get-FloppyDrive | Select Parent, Name, ConnectionState

If a virtual machine has a floppy drive connected, this is a finding.'
  desc 'fix', 'Floppy drives are no longer visible through the vSphere Client and must be done via the API or PowerCLI.

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-FloppyDrive | Remove-FloppyDrive

Note: The VM must be powered off to remove the floppy drive.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 Virtual Machine'
  tag check_id: 'C-60132r886412_chk'
  tag severity: 'medium'
  tag gid: 'V-256457'
  tag rid: 'SV-256457r886414_rule'
  tag stig_id: 'VMCH-70-000008'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60075r886413_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
