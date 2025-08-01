control 'SV-239330' do
  title 'The ESXi host must centrally review and analyze audit records from multiple components within the system by configuring remote logging.'
  desc 'Remote logging to a central log host provides a secure, centralized store for ESXi logs. By gathering host log files onto a central host, it can more easily monitor all hosts with a single tool. It can also do aggregate analysis and searching to look for such things as coordinated attacks on multiple hosts. Logging to a secure, centralized log server also helps prevent log tampering and provides a long-term audit record.

'
  desc 'check', 'From the vSphere Client, select the ESXi host and go to Configuration >> Advanced Settings. 

Select the "Syslog.global.logHost" value and verify it is set to a site-specific syslog server hostname.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost

If the "Syslog.global.logHost" value is not set to a site-specific syslog server, this is a finding.'
  desc 'fix', 'From the vSphere Client, select the ESXi host and go to Configuration >> Advanced Settings. 

Select the "Syslog.global.logHost" value and configure it to a site-specific syslog server.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Syslog.global.logHost | Set-AdvancedSetting -Value "<insert syslog server hostname>"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42563r674917_chk'
  tag severity: 'medium'
  tag gid: 'V-239330'
  tag rid: 'SV-239330r674919_rule'
  tag stig_id: 'ESXI-67-100004'
  tag gtitle: 'SRG-OS-000051-VMM-000230'
  tag fix_id: 'F-42522r674918_fix'
  tag satisfies: ['SRG-OS-000051-VMM-000230', 'SRG-OS-000058-VMM-000270', 'SRG-OS-000059-VMM-000280']
  tag 'documentable'
  tag cci: ['CCI-000154', 'CCI-000163', 'CCI-000164']
  tag nist: ['AU-6 (4)', 'AU-9 a', 'AU-9 a']
end
