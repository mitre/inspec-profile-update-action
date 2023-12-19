control 'SV-77729' do
  title 'The VMM must be configured to disable non-essential capabilities by disabling SSH.'
  desc 'The ESXi Shell is an interactive command line interface (CLI) available at the ESXi server console. The ESXi shell provides temporary access to commands essential for server maintenance. Intended primarily for use in break-fix scenarios, the ESXi shell is well suited for checking and modifying configuration details, not always generally accessible, using the vSphere Client. The ESXi shell is accessible remotely using SSH by users with the Administrator role. Under normal operating conditions, SSH access to the host must be disabled as is the default.  As with the ESXi shell, SSH is also intended only for temporary use during break-fix scenarios. SSH must therefore be disabled under normal operating conditions and must only be enabled for diagnostics or troubleshooting. Remote access to the host must therefore be limited to the vSphere Client at all other times.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Security Profile.  Under Services select Edit and view the "SSH" service and verify it is stopped.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"}

If the ESXi SSH service is running, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Security Profile.  Under Services select Edit then select the SSH service and click options.  Change the service to "Start and stop manually" and stop the service and click OK.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"} | Set-VMHostService -Policy Off
Get-VMHost | Get-VMHostService | Where {$_.Label -eq "SSH"} | Stop-VMHostService'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63973r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63239'
  tag rid: 'SV-77729r1_rule'
  tag stig_id: 'ESXI-06-000035'
  tag gtitle: 'SRG-OS-000095-VMM-000480'
  tag fix_id: 'F-69157r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
