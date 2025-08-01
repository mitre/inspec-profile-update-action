control 'SV-207644' do
  title 'The ESXi host must logout of the console UI after 10 minutes.'
  desc 'When the Direct console user interface (DCUI) is enabled and logged in it should be automatically logged out if left logged in to avoid unauthorized privilege gains.  The DcuiTimeOut defines a window of time after which the DCUI will be logged out.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Select the UserVars.DcuiTimeOut value and verify it is set to 600 (10 Minutes).

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut

If the UserVars.DcuiTimeOut setting is not set to 600, this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Advanced System Settings. Click Edit and select the UserVars.DcuiTimeOut value and configure it to 600.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7899r364331_chk'
  tag severity: 'medium'
  tag gid: 'V-207644'
  tag rid: 'SV-207644r378994_rule'
  tag stig_id: 'ESXI-65-000043'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-7899r364332_fix'
  tag 'documentable'
  tag legacy: ['SV-104119', 'V-94033']
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
