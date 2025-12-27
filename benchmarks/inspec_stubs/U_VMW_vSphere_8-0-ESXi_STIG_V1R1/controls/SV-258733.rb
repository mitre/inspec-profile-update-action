control 'SV-258733' do
  title 'The ESXi must produce audit records containing information to establish what type of events occurred.'
  desc 'Without establishing what types of events occurred, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack. 

'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "Config.HostAgent.log.level" value and verify it is set to "info".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level

If the "Config.HostAgent.log.level" setting is not set to "info", this is a finding.

Note: Verbose logging level is acceptable for troubleshooting purposes.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "Config.HostAgent.log.level" value and configure it to "info".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level | Set-AdvancedSetting -Value "info"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62473r933258_chk'
  tag severity: 'medium'
  tag gid: 'V-258733'
  tag rid: 'SV-258733r933260_rule'
  tag stig_id: 'ESXI-80-000015'
  tag gtitle: 'SRG-OS-000037-VMM-000150'
  tag fix_id: 'F-62382r933259_fix'
  tag satisfies: ['SRG-OS-000037-VMM-000150', 'SRG-OS-000063-VMM-000310']
  tag 'documentable'
  tag cci: ['CCI-000130', 'CCI-000171']
  tag nist: ['AU-3 a', 'AU-12 b']
end
