control 'SV-77727' do
  title 'The system must disable the Managed Object Browser (MOB).'
  desc 'The Managed Object Browser (MOB) provides a way to explore the object model used by the VMkernel to manage the host and enables configurations to be changed as well. This interface is meant to be used primarily for debugging the vSphere SDK, but because there are no access controls it could also be used as a method obtain information about a host being targeted for unauthorized access.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Config.HostAgent.plugins.solo.enableMob value and verify it is set to false.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob

If the Config.HostAgent.plugins.solo.enableMob setting is not set to false, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Config.HostAgent.plugins.solo.enableMob value and configure it to false.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.solo.enableMob | Set-AdvancedSetting -Value false'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63971r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63237'
  tag rid: 'SV-77727r1_rule'
  tag stig_id: 'ESXI-06-000034'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag fix_id: 'F-69155r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
