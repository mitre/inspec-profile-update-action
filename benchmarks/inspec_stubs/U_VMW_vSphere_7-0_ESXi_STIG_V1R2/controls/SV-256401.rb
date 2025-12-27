control 'SV-256401' do
  title 'The ESXi host must disable ESXi Shell unless needed for diagnostics or troubleshooting.'
  desc 'The ESXi Shell is an interactive command line environment available locally from the Direct Console User Interface (DCUI) or remotely via SSH. Activities performed from the ESXi Shell bypass vCenter role-based access control (RBAC) and audit controls.

The ESXi shell must only be turned on when needed to troubleshoot/resolve problems that cannot be fixed through the vSphere client.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Services.

Under "Services", locate the "ESXi Shell" service and verify it is "Stopped".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"}

If the ESXi Shell service is "Running", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Services.

Under "Services", select the "ESXi Shell" service and click the "Stop" button. 

Click the "Edit Startup policy..." button. 

Select the "Start and stop manually" radio button. 

Click "OK".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Set-VMHostService -Policy Off
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Stop-VMHostService'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60076r885982_chk'
  tag severity: 'medium'
  tag gid: 'V-256401'
  tag rid: 'SV-256401r885984_rule'
  tag stig_id: 'ESXI-70-000036'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag fix_id: 'F-60019r885983_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
