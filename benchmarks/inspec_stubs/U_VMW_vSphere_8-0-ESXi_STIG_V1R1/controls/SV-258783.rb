control 'SV-258783' do
  title 'The ESXi Common Information Model (CIM) service must be disabled.'
  desc 'The CIM system provides an interface that enables hardware-level management from remote applications via a set of standard application programming interfaces (APIs). These APIs are consumed by external applications such as HP SIM or Dell OpenManage for agentless, remote hardware monitoring of the ESXi host.

To reduce attack surface area and following the minimum functionality principal, the CIM service must be disabled unless explicitly needed and approved.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Services.

Under "Services", locate the "CIM Server" service and verify it is "Stopped" and the "Startup Policy" is set to "Start and stop manually".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "CIM Server"}

If the "CIM Server" service does not have a "Policy" of "off" or is running, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Services.

Under "Services" select the "CIM Server" service and click the "Stop" button.

Click "Edit Startup policy..." and select the "Start and stop manually" radio button. Click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "CIM Server"} | Set-VMHostService -Policy Off
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "CIM Server"} | Stop-VMHostService'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62523r933408_chk'
  tag severity: 'medium'
  tag gid: 'V-258783'
  tag rid: 'SV-258783r933410_rule'
  tag stig_id: 'ESXI-80-000228'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62432r933409_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
