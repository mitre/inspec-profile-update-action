control 'SV-258731' do
  title 'The ESXi host client must be configured with an idle session timeout.'
  desc '<0> [object Object]'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.HostClientSessionTimeout" value and verify it is set to "900" or less.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout

If the "UserVars.HostClientSessionTimeout" setting is not set to "900" or less, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "UserVars.HostClientSessionTimeout" value and configure it to "900".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout | Set-AdvancedSetting -Value "900"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62471r933252_chk'
  tag severity: 'medium'
  tag gid: 'V-258731'
  tag rid: 'SV-258731r933254_rule'
  tag stig_id: 'ESXI-80-000010'
  tag gtitle: 'SRG-OS-000029-VMM-000100'
  tag fix_id: 'F-62380r933253_fix'
  tag cci: ['CCI-000057']
  tag nist: ['AC-11 a']
end
