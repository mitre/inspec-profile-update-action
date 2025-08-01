control 'SV-77719' do
  title 'The system must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what types of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Config.HostAgent.log.level value and verify it is set to the default level of info.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level

If the Config.HostAgent.log.level setting is not set to info, this is a finding.

Note: Verbose logging level is acceptable for troubleshooting purposes.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Config.HostAgent.log.level value and configure it to info.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value "info"'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63963r1_chk'
  tag severity: 'low'
  tag gid: 'V-63229'
  tag rid: 'SV-77719r1_rule'
  tag stig_id: 'ESXI-06-000030'
  tag gtitle: 'SRG-OS-000037-VMM-000150'
  tag fix_id: 'F-69147r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
