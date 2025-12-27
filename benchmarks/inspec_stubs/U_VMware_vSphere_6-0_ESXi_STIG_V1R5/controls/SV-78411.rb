control 'SV-78411' do
  title 'The VMM must, at a minimum, off-load interconnected systems in real time and off-load standalone systems weekly by configuring remote logging.'
  desc 'Remote logging to a central log host provides a secure, centralized store for ESXi logs. By gathering host log files onto a central host it can more easily monitor all hosts with a single tool. It can also do aggregate analysis and searching to look for such things as coordinated attacks on multiple hosts. Logging to a secure, centralized log server also helps prevent log tampering and also provides a long-term audit record.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Syslog.global.logHost value and verify it is set to a site specific syslog server hostname.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost

If the Syslog.global.logHost setting is not set to a site specific syslog server, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the Syslog.global.logHost value and configure it to a site specific syslog server.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value "<insert syslog server hostname>"'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64671r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63921'
  tag rid: 'SV-78411r1_rule'
  tag stig_id: 'ESXI-06-500004'
  tag gtitle: 'SRG-OS-000479-VMM-001990'
  tag fix_id: 'F-69849r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
