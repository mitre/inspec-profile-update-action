control 'SV-258736' do
  title 'The ESXi host must be configured to disable nonessential capabilities by disabling the Managed Object Browser (MOB).'
  desc 'The MOB provides a way to explore the object model used by the VMkernel to manage the host and enables configurations to be changed. This interface is meant to be used primarily for debugging the vSphere Software Development Kit (SDK), but because there are no access controls it could also be used as a method to obtain information about a host being targeted for unauthorized access.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Config.HostAgent.plugins.solo.enableMob" value and verify it is set to "false".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob

If the "Config.HostAgent.plugins.solo.enableMob" setting is not set to "false", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Config.HostAgent.plugins.solo.enableMob" value and configure it to "false".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value false'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62476r933267_chk'
  tag severity: 'medium'
  tag gid: 'V-258736'
  tag rid: 'SV-258736r933269_rule'
  tag stig_id: 'ESXI-80-000047'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag fix_id: 'F-62385r933268_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
