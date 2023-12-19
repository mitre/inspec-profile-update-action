control 'SV-258757' do
  title 'The ESXi host must set a timeout to automatically end idle DCUI sessions after 10 minutes.'
  desc 'When the Direct Console User Interface (DCUI) is enabled and logged in, it should be automatically logged out if left logged on to avoid access by unauthorized persons. The "DcuiTimeOut" setting defines a window of time after which the DCUI will be logged out.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.DcuiTimeOut" value and verify it is set to less than "600" and not "0".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut

If the "UserVars.DcuiTimeOut" setting is set to a value greater than "600" or "0", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "UserVars.DcuiTimeOut" value and configure it to "600".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62497r933330_chk'
  tag severity: 'medium'
  tag gid: 'V-258757'
  tag rid: 'SV-258757r933332_rule'
  tag stig_id: 'ESXI-80-000196'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-62406r933331_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
