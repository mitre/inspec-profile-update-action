control 'SV-258798' do
  title 'The ESXi host must enforce the exclusive running of executables from approved VIBs.'
  desc 'The "execInstalledOnly" advanced ESXi boot option, when set to TRUE, guarantees that the VMkernel executes only those binaries that have been packaged as part of a signed VIB. While this option is effective on its own, it can be further enhanced by telling the Secure Boot to check with the TPM to make sure that the boot process does not proceed unless this setting is enabled. This further protects against malicious offline changes to ESXi configuration to disable the "execInstalledOnly" option.'
  desc 'check', 'If the ESXi host does not have a compatible TPM, this finding is downgraded to a CAT III.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "VMkernel.Boot.execInstalledOnly" value and verify that it is "true".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly

If the "VMkernel.Boot.execInstalledOnly" setting is not "true", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "VMkernel.Boot.execInstalledOnly" value and configure it to "true".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly | Set-AdvancedSetting -Value True'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62538r933453_chk'
  tag severity: 'medium'
  tag gid: 'V-258798'
  tag rid: 'SV-258798r933455_rule'
  tag stig_id: 'ESXI-80-000244'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62447r933454_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
