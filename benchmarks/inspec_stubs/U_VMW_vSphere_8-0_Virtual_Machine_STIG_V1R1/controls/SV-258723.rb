control 'SV-258723' do
  title 'Virtual machines (VMs) must remove unneeded CD/DVD devices.'
  desc 'Ensure no device is connected to a virtual machine if it is not required. For example, floppy, serial, and parallel ports are rarely used for virtual machines in a data center environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to "Edit Settings".

Review the VMs hardware and verify no CD/DVD drives are connected.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM | Get-CDDrive | Where {$_.extensiondata.connectable.connected -eq $true} | Select Parent,Name

If a virtual machine has a CD/DVD drive connected other than temporarily, this is a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to "Edit Settings".

Select the CD/DVD drive and uncheck "Connected" and "Connect at power on" and remove any attached ISOs.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-CDDrive | Set-CDDrive -NoMedia'
  impact 0.3
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62463r933228_chk'
  tag severity: 'low'
  tag gid: 'V-258723'
  tag rid: 'SV-258723r933230_rule'
  tag stig_id: 'VMCH-80-000210'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62372r933229_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
