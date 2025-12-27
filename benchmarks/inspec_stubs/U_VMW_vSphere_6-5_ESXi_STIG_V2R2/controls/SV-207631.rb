control 'SV-207631' do
  title 'The ESXi host must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what types of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings.  Select the Config.HostAgent.log.level value and verify it is set to "info".

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level

If the Config.HostAgent.log.level setting is not set to info, this is a finding.

Note: Verbose logging level is acceptable for troubleshooting purposes.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Click Edit and select the Config.HostAgent.log.level value and configure it to "info".

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value "info"'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7886r364292_chk'
  tag severity: 'low'
  tag gid: 'V-207631'
  tag rid: 'SV-207631r378616_rule'
  tag stig_id: 'ESXI-65-000030'
  tag gtitle: 'SRG-OS-000037-VMM-000150'
  tag fix_id: 'F-7886r364293_fix'
  tag 'documentable'
  tag legacy: ['V-94007', 'SV-104093']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
