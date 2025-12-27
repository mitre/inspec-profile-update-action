control 'SV-258706' do
  title 'Virtual machines (VMs) must have virtual disk shrinking disabled.'
  desc "Shrinking a virtual disk reclaims unused space in it. If there is empty space in the disk, this process reduces the amount of space the virtual disk occupies on the host drive. Normal users and processes (those without root or administrator privileges) within virtual machines have the capability to invoke this procedure.

However, if this is done repeatedly, the virtual disk can become unavailable while this shrinking is being performed, effectively causing a denial of service. In most datacenter environments, disk shrinking is not done, so this feature must be disabled. Repeated disk shrinking can make a virtual disk unavailable. The capability to shrink is available to nonadministrative users operating within the VM's guest operating system."
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Verify the "isolation.tools.diskShrink.disable" value is set to "true".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.diskShrink.disable

If the virtual machine advanced setting "isolation.tools.diskShrink.disable" is not set to "true", this is a finding.

If the virtual machine advanced setting "isolation.tools.diskShrink.disable" does not exist, this is not a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Find the "isolation.tools.diskShrink.disable" value and set it to "true".

If the setting does not exist no action is needed. 

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.diskShrink.disable | Set-AdvancedSetting -Value true

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62446r933177_chk'
  tag severity: 'medium'
  tag gid: 'V-258706'
  tag rid: 'SV-258706r933179_rule'
  tag stig_id: 'VMCH-80-000193'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62355r933178_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
