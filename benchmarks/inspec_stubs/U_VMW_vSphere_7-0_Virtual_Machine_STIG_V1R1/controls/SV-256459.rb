control 'SV-256459' do
  title 'Unauthorized parallel devices must be disconnected on the virtual machine (VM).'
  desc 'Ensure no device is connected to a virtual machine if it is not required. For example, floppy, serial, and parallel ports are rarely used for virtual machines in a data center environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc 'check', %q(From the vSphere Client, right-click the Virtual Machine and go to "Edit Settings".

Review the VM's hardware and verify no parallel devices exist.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "parallel"}

If a virtual machine has a parallel device present, this is a finding.)
  desc 'fix', 'The VM must be powered off to remove a parallel device.

From the vSphere Client, right-click the Virtual Machine and go to "Edit Settings".

Select the parallel device, click the circled "X" to remove it, and click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 Virtual Machine'
  tag check_id: 'C-60134r886418_chk'
  tag severity: 'medium'
  tag gid: 'V-256459'
  tag rid: 'SV-256459r886420_rule'
  tag stig_id: 'VMCH-70-000010'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60077r886419_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
