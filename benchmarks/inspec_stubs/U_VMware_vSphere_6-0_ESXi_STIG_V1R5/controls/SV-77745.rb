control 'SV-77745' do
  title 'The system must logout of the console UI after a predetermined period.'
  desc 'When the Direct console user interface (DCUI) is enabled and logged in it should be automatically logged out if left logged in to avoid unauthorized privilege gains.  The DcuiTimeOut defines a window of time after which the DCUI will be logged out.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the UserVars.DcuiTimeOut value and verify it is set to 600 (10 Minutes).

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut

If the UserVars.DcuiTimeOut setting is not set to 600, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the UserVars.DcuiTimeOut value and configure it to 600.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name UserVars.DcuiTimeOut | Set-AdvancedSetting -Value 600'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63989r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63255'
  tag rid: 'SV-77745r1_rule'
  tag stig_id: 'ESXI-06-000043'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-69173r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
