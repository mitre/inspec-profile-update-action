control 'SV-239297' do
  title 'The ESXi host must terminate shell services after 10 minutes.'
  desc 'When the ESXi Shell or SSH services are enabled on a host, they will run indefinitely. To avoid having these services left running, set the "ESXiShellTimeOut". The "ESXiShellTimeOut" defines a window of time after which the ESXi Shell and SSH services will be stopped automatically.

'
  desc 'check', 'From the vSphere Client, select the ESXi Host and go to Configure >> System >> Advanced System Settings. 

Select the "UserVars.ESXiShellTimeOut" value and verify it is set to "600" (10 Minutes).

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut

If the "UserVars.ESXiShellTimeOut" setting is not set to "600", this is a finding.'
  desc 'fix', 'From the vSphere Client, select the ESXi host and go to Configure >> System >> Advanced System Settings. 

Click "Edit", select the "UserVars.ESXiShellTimeOut" value, and configure it to "600".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42530r674818_chk'
  tag severity: 'medium'
  tag gid: 'V-239297'
  tag rid: 'SV-239297r878140_rule'
  tag stig_id: 'ESXI-67-000042'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-42489r674819_fix'
  tag satisfies: ['SRG-OS-000163-VMM-000700', 'SRG-OS-000279-VMM-001010']
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-002361']
  tag nist: ['SC-10', 'AC-12']
end
