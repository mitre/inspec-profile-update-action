control 'SV-77731' do
  title 'The system must disable ESXi Shell unless needed for diagnostics or troubleshooting.'
  desc 'The ESXi Shell is an interactive command line environment available locally from the DCUI or remotely via SSH. Activities performed from the ESXi Shell bypass vCenter RBAC and audit controls. The ESXi shell should only be turned on when needed to troubleshoot/resolve problems that cannot be fixed through the vSphere client.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Security Profile.  Under Services select Edit and view the "ESXi Shell" service and verify it is stopped.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"}

If the ESXi Shell service is running, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Security Profile.  Under Services select Edit then select the ESXi Shell service and click options.  Change the service to "Start and stop manually" and stop the service and click OK.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Set-VMHostService -Policy Off
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "ESXi Shell"} | Stop-VMHostService'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63975r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63241'
  tag rid: 'SV-77731r1_rule'
  tag stig_id: 'ESXI-06-000036'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag fix_id: 'F-69159r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
