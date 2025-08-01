control 'SV-256461' do
  title 'Unauthorized USB devices must be disconnected on the virtual machine (VM).'
  desc 'Ensure no device is connected to a virtual machine if it is not required. For example, floppy, serial, and parallel ports are rarely used for virtual machines in a data center environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc 'check', %q(From the vSphere Client, right-click the Virtual Machine and go to "Edit Settings".

Review the VM's hardware and verify no USB devices exist.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following commands:

Get-VM | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "usb"}
Get-VM | Get-UsbDevice

If a virtual machine has any USB devices or USB controllers present, this is a finding.

If USB smart card readers are used to pass smart cards through the VM console to a VM, the use of a USB controller and USB devices for that purpose is not a finding.)
  desc 'fix', 'From the vSphere Client, right-click the Virtual Machine and go to "Edit Settings".

Select the USB controller, click the circled "X" to remove it, and click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-USBDevice | Remove-USBDevice

Note: This will not remove the USB controller, just any connected devices.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 Virtual Machine'
  tag check_id: 'C-60136r886424_chk'
  tag severity: 'medium'
  tag gid: 'V-256461'
  tag rid: 'SV-256461r886426_rule'
  tag stig_id: 'VMCH-70-000012'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60079r886425_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
