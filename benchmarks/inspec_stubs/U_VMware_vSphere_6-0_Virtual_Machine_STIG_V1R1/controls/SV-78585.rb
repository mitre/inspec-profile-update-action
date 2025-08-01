control 'SV-78585' do
  title 'The system must disconnect unauthorized CD/DVD devices.'
  desc 'Ensure that no device is connected to a virtual machine if it is not required. For example, floppy, serial and parallel ports are rarely used for virtual machines in a datacenter environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings.  Review the VMs hardware and verify no CD/DVD drives are connected.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM | Get-CDDrive | Where {$_.extensiondata.connectable.connected -eq $true} | Select Parent,Name

If a virtual machine has a CD/DVD drive connected other than temporarily, this is a finding.'
  desc 'fix', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings.  Select the CD/DVD drive and uncheck "Connected" and "Connect at power on" and remove any attached ISOs.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-CDDrive | Set-CDDrive -NoMedia'
  impact 0.3
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64845r1_chk'
  tag severity: 'low'
  tag gid: 'V-64095'
  tag rid: 'SV-78585r1_rule'
  tag stig_id: 'VMCH-06-000029'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-70023r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
