control 'SV-256407' do
  title 'The ESXi host must log out of the console UI after two minutes.'
  desc 'When the Direct Console User Interface (DCUI) is enabled and logged in, it should be automatically logged out if left logged on to avoid access by unauthorized persons. The "DcuiTimeOut" setting defines a window of time after which the DCUI will be logged out.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.DcuiTimeOut" value and verify it is set to "120" (two minutes).

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut

If the "UserVars.DcuiTimeOut" setting is not set to "120", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "UserVars.DcuiTimeOut" value and configure it to "120".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 120'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60082r886000_chk'
  tag severity: 'medium'
  tag gid: 'V-256407'
  tag rid: 'SV-256407r886002_rule'
  tag stig_id: 'ESXI-70-000043'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-60025r886001_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
