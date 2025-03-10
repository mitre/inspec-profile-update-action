control 'SV-256475' do
  title 'Log retention must be configured properly on the virtual machine (VM).'
  desc 'The ESXi hypervisor maintains logs for each individual VM by default. These logs contain information including but not limited to power events, system failure information, tools status and activity, time sync, virtual hardware changes, vMotion migrations, and machine clones.

By default, 10 of these logs are retained. This is normally sufficient for most environments, but this configuration must be verified and maintained.'
  desc 'check', 'From the vSphere Client, select the Virtual Machine, right-click, and go to Edit Settings >> VM Options tab >> Advanced >> Configuration Parameters >> Edit Configuration.

Find the "log.keepOld" value and verify it is set to "10".

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

Get-VM "VM Name" | Get-AdvancedSetting -Name log.keepOld

If the virtual machine advanced setting "log.keepOld" is not set to "10", this is a finding.

If the virtual machine advanced setting "log.keepOld" does not exist, this is not a finding.'
  desc 'fix', 'From the vSphere Client, select the Virtual Machine, right-click and go to Edit Settings >> VM Options tab >> Advanced >> Configuration Parameters >> Edit Configuration.

Find the "log.keepOld" value and set it to "10".

Note: The VM must be powered off to modify the advanced settings through the vSphere Client. It is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. In this case, the modified settings will not take effect until a cold boot of the VM.

or

From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the provided commands as shown below.

If the setting does not exist, run:

Get-VM "VM Name" | New-AdvancedSetting -Name log.keepOld -Value 10

If the setting exists, run:

Get-VM "VM Name" | Get-AdvancedSetting -Name log.keepOld | Set-AdvancedSetting -Value 10'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 Virtual Machine'
  tag check_id: 'C-60150r886466_chk'
  tag severity: 'medium'
  tag gid: 'V-256475'
  tag rid: 'SV-256475r886468_rule'
  tag stig_id: 'VMCH-70-000027'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60093r886467_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
