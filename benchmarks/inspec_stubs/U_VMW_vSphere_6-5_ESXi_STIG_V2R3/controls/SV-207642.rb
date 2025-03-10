control 'SV-207642' do
  title 'The ESXi host must set a timeout to automatically disable idle sessions after 10 minutes.'
  desc 'If a user forgets to log out of their SSH session, the idle connection will remains open indefinitely, increasing the potential for someone to gain privileged access to the host.  The ESXiShellInteractiveTimeOut allows you to automatically terminate idle shell sessions.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Select the UserVars.ESXiShellInteractiveTimeOut value and verify it is set to 600 (10 Minutes).

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut

If the UserVars.ESXiShellInteractiveTimeOut setting is not set to 600, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Click Edit and select the UserVars.ESXiShellInteractiveTimeOut value and configure it to 600.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 600'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7897r364325_chk'
  tag severity: 'medium'
  tag gid: 'V-207642'
  tag rid: 'SV-207642r378994_rule'
  tag stig_id: 'ESXI-65-000041'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-7897r364326_fix'
  tag 'documentable'
  tag legacy: ['SV-104115', 'V-94029']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
