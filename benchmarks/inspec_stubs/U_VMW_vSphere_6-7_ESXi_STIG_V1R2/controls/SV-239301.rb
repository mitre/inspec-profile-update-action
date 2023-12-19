control 'SV-239301' do
  title 'The ESXi host must configure NTP time synchronization.'
  desc 'To ensure the accuracy of the system clock, it must be synchronized with an authoritative time source within DoD. Many system functions, including time-based logon and activity restrictions, automated reports, system logs, and audit records, depend on an accurate system clock. If there is no confidence in the correctness of the system clock, time-based functions may not operate as intended and records may be of diminished value.

'
  desc 'check', 'From the vSphere Client, select the ESXi host and go to Configure >> System >> Time Configuration. 

Click "Edit" to verify the configured NTP servers and service startup policy.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-VMHostNTPServer
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"}

If the NTP service is not configured with authoritative DoD time sources or the service does not have a "Policy" of "on" or is stopped, this is a finding.'
  desc 'fix', 'From the vSphere Client, select the ESXi host and go to Configure >> System >> Time Configuration. 

Click "Edit" to configure the NTP service to start and stop with the host and with authoritative DoD time sources.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

$NTPServers = "ntpserver1","ntpserver2"
Get-VMHost | Add-VMHostNTPServer $NTPServers
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Start-VMHostService'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42534r674830_chk'
  tag severity: 'medium'
  tag gid: 'V-239301'
  tag rid: 'SV-239301r674832_rule'
  tag stig_id: 'ESXI-67-000046'
  tag gtitle: 'SRG-OS-000355-VMM-001330'
  tag fix_id: 'F-42493r674831_fix'
  tag satisfies: ['SRG-OS-000355-VMM-001330', 'SRG-OS-000356-VMM-001340']
  tag 'documentable'
  tag cci: ['CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)']
end
