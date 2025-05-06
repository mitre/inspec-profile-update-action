control 'SV-77999' do
  title 'The VMM must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
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
  tag check_id: 'C-64259r1_chk'
  tag severity: 'low'
  tag gid: 'V-63509'
  tag rid: 'SV-77999r1_rule'
  tag stig_id: 'ESXI-06-100030'
  tag gtitle: 'SRG-OS-000063-VMM-000310'
  tag fix_id: 'F-69439r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
