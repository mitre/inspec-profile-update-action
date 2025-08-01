control 'SV-239343' do
  title 'Unauthorized USB devices must be disconnected on the virtual machine.'
  desc 'Ensure that no device is connected to a virtual machine if it is not required. For example, floppy, serial and parallel ports are rarely used for virtual machines in a datacenter environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc 'check', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings. Review the VMs hardware and verify no USB devices exist.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following commands:

Get-VM | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "usb"}
Get-VM | Get-UsbDevice

If a virtual machine has any USB devices or USB controllers present, this is a finding.

If USB smart card readers are used to pass smart cards through the VM console to a VM then the use of a USB controller and USB devices for that purpose is not a finding.'
  desc 'fix', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings. Select the USB controller and click the circle-x to remove then OK.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-USBDevice | Remove-USBDevice

Note: This will not remove the USB controller just any connected devices.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Virtual Machine'
  tag check_id: 'C-42576r679576_chk'
  tag severity: 'medium'
  tag gid: 'V-239343'
  tag rid: 'SV-239343r679578_rule'
  tag stig_id: 'VMCH-67-000012'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-42535r679577_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
