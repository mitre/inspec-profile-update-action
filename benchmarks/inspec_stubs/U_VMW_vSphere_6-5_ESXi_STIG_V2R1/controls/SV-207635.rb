control 'SV-207635' do
  title 'The ESXi host must disable the Managed Object Browser (MOB).'
  desc 'The Managed Object Browser (MOB) provides a way to explore the object model used by the VMkernel to manage the host and enables configurations to be changed as well. This interface is meant to be used primarily for debugging the vSphere SDK, but because there are no access controls it could also be used as a method obtain information about a host being targeted for unauthorized access.  By default this is disabled for ESXi in version 6.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Select the Config.HostAgent.plugins.solo.enableMob value and verify it is set to false.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob

If the Config.HostAgent.plugins.solo.enableMob setting is not set to false, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Click Edit and select the Config.HostAgent.plugins.solo.enableMob value and configure it to false.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value false'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7890r364304_chk'
  tag severity: 'medium'
  tag gid: 'V-207635'
  tag rid: 'SV-207635r378841_rule'
  tag stig_id: 'ESXI-65-000034'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag fix_id: 'F-7890r364305_fix'
  tag 'documentable'
  tag legacy: ['V-94015', 'SV-104101']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
