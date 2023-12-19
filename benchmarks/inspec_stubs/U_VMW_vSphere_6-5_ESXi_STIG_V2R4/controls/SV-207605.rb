control 'SV-207605' do
  title 'Remote logging for ESXi hosts must be configured.'
  desc 'Remote logging to a central log host provides a secure, centralized store for ESXi logs. By gathering host log files onto a central host it can more easily monitor all hosts with a single tool. It can also do aggregate analysis and searching to look for such things as coordinated attacks on multiple hosts. Logging to a secure, centralized log server also helps prevent log tampering and also provides a long-term audit record.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings.  Select the Syslog.global.logHost value and verify it is set to a site specific syslog server hostname.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost

If the Syslog.global.logHost setting is not set to a site specific syslog server, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Click Edit and select the Syslog.global.logHost value and configure it to a site specific syslog server.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value "<syslog server hostname>"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7860r364214_chk'
  tag severity: 'medium'
  tag gid: 'V-207605'
  tag rid: 'SV-207605r378607_rule'
  tag stig_id: 'ESXI-65-000004'
  tag gtitle: 'SRG-OS-000032-VMM-000130'
  tag fix_id: 'F-7860r364215_fix'
  tag 'documentable'
  tag legacy: ['V-93955', 'SV-104041']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
