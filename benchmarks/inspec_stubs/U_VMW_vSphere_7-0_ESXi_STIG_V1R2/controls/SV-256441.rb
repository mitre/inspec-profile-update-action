control 'SV-256441' do
  title 'The ESXi Host Client must be configured with a session timeout.'
  desc '<0> [object Object]'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.HostClientSessionTimeout" value and verify it is set to "600".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout

If the "UserVars.HostClientSessionTimeout" setting is not set to "600", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.HostClientSessionTimeout" value and set it to "600".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.HostClientSessionTimeout | Set-AdvancedSetting -Value "600"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60116r886102_chk'
  tag severity: 'medium'
  tag gid: 'V-256441'
  tag rid: 'SV-256441r886104_rule'
  tag stig_id: 'ESXI-70-000089'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60059r886103_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
