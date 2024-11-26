control 'SV-258786' do
  title 'The ESXi host OpenSLP service must be disabled.'
  desc 'OpenSLP implements the Service Location Protocol to help CIM clients discover CIM servers over TCP 427. This service is not widely needed and has had vulnerabilities exposed in the past. To reduce attack surface area and following the minimum functionality principal, the OpenSLP service must be disabled unless explicitly needed and approved.

Note: Disabling the OpenSLP service may affect monitoring and third-party systems that use the WBEM DTMF protocols.'
  desc 'check', 'From the vSphere Client go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Services.

Under "Services", locate the "slpd" service and verify it is "Stopped" and the "Startup Policy" is set to "Start and stop manually".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"}

If the slpd service does not have a "Policy" of "off" or is running, this is a finding.'
  desc 'fix', 'From the vSphere Client go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Services.

Under "Services" select the "slpd" service and click the "Stop" button.

Click "Edit Startup policy..." and select the "Start and stop manually" radio button. Click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"} | Set-VMHostService -Policy Off
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "slpd"} | Stop-VMHostService'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62526r933417_chk'
  tag severity: 'medium'
  tag gid: 'V-258786'
  tag rid: 'SV-258786r933419_rule'
  tag stig_id: 'ESXI-80-000231'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62435r933418_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
