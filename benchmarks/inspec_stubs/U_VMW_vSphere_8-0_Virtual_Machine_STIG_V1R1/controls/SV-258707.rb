control 'SV-258707' do
  title 'Virtual machines (VMs) must have virtual disk wiping disabled.'
  desc "Shrinking and wiping (erasing) a virtual disk reclaims unused space in it. If there is empty space in the disk, this process reduces the amount of space the virtual disk occupies on the host drive. Normal users and processes (those without root or administrator privileges) within virtual machines have the capability to invoke this procedure.

However, if this is done repeatedly, the virtual disk can become unavailable while this shrinking is being performed, effectively causing a denial of service. In most datacenter environments, disk shrinking is not done, so this feature must be disabled. Repeated disk shrinking can make a virtual disk unavailable. The capability to wipe (erase) is available to nonadministrative users operating within the VM's guest operating system."
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Verify the "isolation.tools.diskWiper.disable" value is set to "true".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.diskWiper.disable

If the virtual machine advanced setting "isolation.tools.diskWiper.disable" is not set to "true", this is a finding.

If the virtual machine advanced setting "isolation.tools.diskWiper.disable" does not exist, this is not a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Find the "isolation.tools.diskWiper.disable" value and set it to "true".

If the setting does not exist no action is needed. 

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.diskWiper.disable | Set-AdvancedSetting -Value true

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62447r933180_chk'
  tag severity: 'medium'
  tag gid: 'V-258707'
  tag rid: 'SV-258707r933182_rule'
  tag stig_id: 'VMCH-80-000194'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62356r933181_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
