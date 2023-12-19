control 'SV-258725' do
  title 'Virtual machines (VMs) must remove unneeded serial devices.'
  desc 'Ensure no device is connected to a virtual machine if it is not required. For example, floppy, serial, and parallel ports are rarely used for virtual machines in a data center environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to "Edit Settings".

Review the VMs hardware and verify no serial devices exist.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "serial"}

If a virtual machine has a serial device present, this is a finding.'
  desc 'fix', 'The VM must be powered off to remove a serial device.

For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to "Edit Settings".

Select the serial device, click the circled "X" to remove it, and click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62465r933234_chk'
  tag severity: 'medium'
  tag gid: 'V-258725'
  tag rid: 'SV-258725r933236_rule'
  tag stig_id: 'VMCH-80-000212'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62374r933235_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
