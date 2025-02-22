control 'SV-258719' do
  title 'Virtual machines (VMs) must configure log retention.'
  desc 'The ESXi hypervisor maintains logs for each individual VM by default. These logs contain information including but not limited to power events, system failure information, tools status and activity, time sync, virtual hardware changes, vMotion migrations, and machine clones.

By default, 10 of these logs are retained. This is normally sufficient for most environments, but this configuration must be verified and maintained.'
  desc 'check', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Verify the "log.keepOld" value is set to "10".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name log.keepOld

If the virtual machine advanced setting "log.keepOld" is not set to "10", this is a finding.

If the virtual machine advanced setting "log.keepOld" does NOT exist, this is NOT a finding.'
  desc 'fix', 'For each virtual machine do the following:

From the vSphere Client, right-click the Virtual Machine and go to Edit Settings >> Advanced Parameters.

Find the "log.keepOld" value and set it to "10".

If the setting does not exist no action is needed. 

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name log.keepOld | Set-AdvancedSetting -Value 10

Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 Virtual Machine'
  tag check_id: 'C-62459r933216_chk'
  tag severity: 'medium'
  tag gid: 'V-258719'
  tag rid: 'SV-258719r933218_rule'
  tag stig_id: 'VMCH-80-000206'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62368r933217_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
