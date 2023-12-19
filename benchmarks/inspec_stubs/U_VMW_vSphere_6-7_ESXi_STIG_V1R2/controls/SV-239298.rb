control 'SV-239298' do
  title 'The ESXi host must log out of the console UI after two minutes.'
  desc 'When the direct console user interface (DCUI) is enabled and logged in, it should be automatically logged out if left logged in to avoid access by unauthorized persons. The "DcuiTimeOut" setting defines a window of time after which the DCUI will be logged out.

'
  desc 'check', 'From the vSphere Client, select the ESXi host and go to Configure >> System >> Advanced System Settings. 

Select the "UserVars.DcuiTimeOut" value and verify it is set to "120" (2 minutes).

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut

If the "UserVars.DcuiTimeOut" setting is not set to "120", this is a finding.'
  desc 'fix', 'From the vSphere Client, select the ESXi host and go to Configure >> System >> Advanced System Settings. 

Click "Edit", select the "UserVars.DcuiTimeOut" value, and configure it to "120".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 120'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42531r674821_chk'
  tag severity: 'medium'
  tag gid: 'V-239298'
  tag rid: 'SV-239298r674823_rule'
  tag stig_id: 'ESXI-67-000043'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-42490r674822_fix'
  tag satisfies: ['SRG-OS-000163-VMM-000700', 'SRG-OS-000279-VMM-001010']
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
