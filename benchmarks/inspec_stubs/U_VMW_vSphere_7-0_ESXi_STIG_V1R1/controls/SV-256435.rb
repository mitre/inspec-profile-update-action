control 'SV-256435' do
  title 'The ESXi host OpenSLP service must be disabled.'
  desc 'OpenSLP implements the Service Location Protocol to help CIM clients discover CIM servers over TCP 427. This service is not widely needed and has had vulnerabilities exposed in the past. To reduce attack surface area and following the minimum functionality principal, the OpenSLP service must be disabled unless explicitly needed and approved. 

Note: Disabling the OpenSLP service may affect monitoring and third-party systems that use the WBEM DTMF protocols.'
  desc 'check', 'From the vSphere Client go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Services.

Locate the "slpd" service and verify that the "Daemon" is "Stopped" and the "Startup Policy" is set to "Start and stop manually".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"}

If the slpd service does not have a "Policy" of "off" or is running, this is a finding.'
  desc 'fix', 'From the vSphere Client go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Services.

Select the "slpd" service. If the service is started, click "Stop". 

Click "Edit Startup Policy...". Select "Start and stop manually". Click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"} | Set-VMHostService -Policy Off
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"} | Stop-VMHostService'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60110r886084_chk'
  tag severity: 'medium'
  tag gid: 'V-256435'
  tag rid: 'SV-256435r886086_rule'
  tag stig_id: 'ESXI-70-000083'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60053r886085_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
