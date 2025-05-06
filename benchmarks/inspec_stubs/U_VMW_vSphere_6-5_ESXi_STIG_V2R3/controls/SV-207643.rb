control 'SV-207643' do
  title 'The ESXi host must terminate shell services after 10 minutes.'
  desc 'When the ESXi Shell or SSH services are enabled on a host they will run indefinitely.  To avoid having these services left running set the ESXiShellTimeOut.  The ESXiShellTimeOut defines a window of time after which the ESXi Shell and SSH services will automatically be terminated.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Select the UserVars.ESXiShellTimeOut value and verify it is set to 600 (10 Minutes).

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut

If the UserVars.ESXiShellTimeOut setting is not set to 600, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Click Edit and select the UserVars.ESXiShellTimeOut value and configure it to 600.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7898r364328_chk'
  tag severity: 'medium'
  tag gid: 'V-207643'
  tag rid: 'SV-207643r378994_rule'
  tag stig_id: 'ESXI-65-000042'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-7898r364329_fix'
  tag 'documentable'
  tag legacy: ['SV-104117', 'V-94031']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
