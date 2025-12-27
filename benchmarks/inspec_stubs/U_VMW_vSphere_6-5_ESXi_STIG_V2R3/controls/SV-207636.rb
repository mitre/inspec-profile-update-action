control 'SV-207636' do
  title 'The ESXi host must be configured to disable non-essential capabilities by disabling SSH.'
  desc 'The ESXi Shell is an interactive command line interface (CLI) available at the ESXi server console. The ESXi shell provides temporary access to commands essential for server maintenance. Intended primarily for use in break-fix scenarios, the ESXi shell is well suited for checking and modifying configuration details, not always generally accessible, using the vSphere Client. The ESXi shell is accessible remotely using SSH by users with the Administrator role. Under normal operating conditions, SSH access to the host must be disabled as is the default.  As with the ESXi shell, SSH is also intended only for temporary use during break-fix scenarios. SSH must therefore be disabled under normal operating conditions and must only be enabled for diagnostics or troubleshooting. Remote access to the host must therefore be limited to the vSphere Client at all other times.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Security Profile. Under Services select Edit and view the "SSH" service and verify it is stopped.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"}

If the ESXi SSH service is running, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Security Profile. Under Services select Edit then select the SSH service and click the Stop button to stop the service. Use the pull-down menu to change the Startup policy to "Start and stop manually" and click OK.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"} | Set-VMHostService -Policy Off
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"} | Stop-VMHostService'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7891r364307_chk'
  tag severity: 'medium'
  tag gid: 'V-207636'
  tag rid: 'SV-207636r378841_rule'
  tag stig_id: 'ESXI-65-000035'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag fix_id: 'F-7891r364308_fix'
  tag 'documentable'
  tag legacy: ['SV-104103', 'V-94017']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
