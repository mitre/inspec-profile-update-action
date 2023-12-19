control 'SV-258745' do
  title 'The ESXi host must synchronize internal information system clocks to an authoritative time source.'
  desc 'To ensure the accuracy of the system clock, it must be synchronized with an authoritative time source within DOD. Many system functions, including time-based logon and activity restrictions, automated reports, system logs, and audit records, depend on an accurate system clock. If there is no confidence in the correctness of the system clock, time-based functions may not operate as intended and records may be of diminished value.

'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Time Configuration.

Verify NTP or PTP are configured, and one or more authoritative time sources are listed.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Services.

Verify the NTP or PTP service is running and configured to start and stop with the host.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VMHost | Get-VMHostNTPServer
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon" -or $_.Label -eq "PTP Daemon"}

If the NTP service is not configured with authoritative DOD time sources or the service is not configured to start and stop with the host ("Policy" of "on" in PowerCLI) or is stopped, this is a finding.

If PTP is used instead of NTP, this is not a finding.'
  desc 'fix', 'To configure NTP, perform the following:

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Time Configuration.

Click "Add Service" and select "Network Time Protocol".

Enter or update the NTP servers listed with a comma-separated list of authoritative time servers. Click "OK".

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Services.

Select the "NTP Daemon" service and click "Edit Startup Policy".

Select "Start and stop with host". Click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$NTPServers = "ntpserver1","ntpserver2"
Get-VMHost | Add-VMHostNTPServer $NTPServers
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Set-VMHostService -Policy On
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "NTP Daemon"} | Start-VMHostService

To configure PTP, perform the following:

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Time Configuration.

Click "Add Service" and select "Precision Time Protocol".

Select the network adapter that can receive the PTP traffic.

If NTP servers are available, select "Enable fallback" and enter or update the NTP servers listed with a comma separate list of authoritative time servers. Click "OK".

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Services.

Select the "PTP Daemon" service and click "Edit Startup Policy".

Select "Start and stop with host". Click "OK".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62485r933294_chk'
  tag severity: 'medium'
  tag gid: 'V-258745'
  tag rid: 'SV-258745r933296_rule'
  tag stig_id: 'ESXI-80-000124'
  tag gtitle: 'SRG-OS-000355-VMM-001330'
  tag fix_id: 'F-62394r933295_fix'
  tag satisfies: ['SRG-OS-000355-VMM-001330', 'SRG-OS-000356-VMM-001340']
  tag 'documentable'
  tag cci: ['CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)']
end
