control 'SV-237090' do
  title 'Unauthorized serial devices must be disconnected on the virtual machine.'
  desc 'Ensure that no device is connected to a virtual machine if it is not required. For example, floppy, serial and parallel ports are rarely used for virtual machines in a datacenter environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc 'check', 'From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings. Review the VMs hardware and verify no serial devices exist.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "serial"}

If a virtual machine has a serial device present, this is a finding.'
  desc 'fix', 'The VM must be powered off in order to remove a serial device.

From the vSphere Web Client right-click the Virtual Machine and go to Edit Settings. Select the serial device and click the circle-x to remove then OK.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 Virtual Machine'
  tag check_id: 'C-40309r640105_chk'
  tag severity: 'medium'
  tag gid: 'V-237090'
  tag rid: 'SV-237090r640107_rule'
  tag stig_id: 'VMCH-65-000031'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-40272r640106_fix'
  tag 'documentable'
  tag legacy: ['SV-104449', 'V-94619']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
