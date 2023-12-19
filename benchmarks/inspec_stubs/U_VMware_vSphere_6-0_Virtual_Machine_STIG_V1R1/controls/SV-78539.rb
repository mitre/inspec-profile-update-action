control 'SV-78539' do
  title 'The system must disable virtual disk erasure.'
  desc 'Shrinking and wiping (erasing) a virtual disk reclaims unused space in it. If there is empty space in the disk, this process reduces the amount of space the virtual disk occupies on the host drive. Normal users and processes - that is, users and processes without root or administrator privileges - within virtual machines have the capability to invoke this procedure. However, if this is done repeatedly, the virtual disk can become unavailable while this shrinking is being performed, effectively causing a denial-of-service. In most datacenter environments, disk shrinking is not done, so this feature must be disabled. Repeated disk shrinking can make a virtual disk unavailable. The capability to wipe (erase) is available to non-administrative users operating within the VMs guest OS.'
  desc 'check', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the isolation.tools.diskWiper.disable value and verify it is set to true.

Note:  The VM must be powered off to view the advanced settings through the vSphere Client so it is recommended to view these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.diskWiper.disable

If the virtual machine advanced setting isolation.tools.diskWiper.disable does not exist or is not set to true, this is a finding.'
  desc 'fix', 'From the vSphere Client select the Virtual Machine right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters.  Find the isolation.tools.diskWiper.disable value and set it to true.  If the setting does not exist click "Add Row" to add the setting to the virtual machine.

Note:  The VM must be powered off to configure the advanced settings through the vSphere Client so it is recommended to configure these settings with PowerCLI as it can be done while the VM is powered on.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server run the following command:

If the setting does not exist run:

Get-VM "VM Name" | New-AdvancedSetting -Name isolation.tools.diskWiper.disable -Value true

If the setting exists run:

Get-VM "VM Name" | Get-AdvancedSetting -Name isolation.tools.diskWiper.disable | Set-AdvancedSetting -Value true'
  impact 0.7
  ref 'DPMS Target VMware Virtual Machine 6.x'
  tag check_id: 'C-64799r1_chk'
  tag severity: 'high'
  tag gid: 'V-64049'
  tag rid: 'SV-78539r1_rule'
  tag stig_id: 'VMCH-06-000006'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69977r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
