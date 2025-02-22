control 'SV-258756' do
  title 'The ESXi host must automatically stop shell services after 10 minutes.'
  desc 'When the ESXi Shell or Secure Shell (SSH) services are enabled on a host, they will run indefinitely. To avoid having these services left running, set the "ESXiShellTimeOut". The "ESXiShellTimeOut" defines a window of time after which the ESXi Shell and SSH services will be stopped automatically.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.ESXiShellTimeOut" value and verify it is set to less than "600" and not "0".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut

If the "UserVars.ESXiShellTimeOut" setting is set to a value greater than "600" or "0", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "UserVars.ESXiShellTimeOut" value and configure it to "600".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62496r933327_chk'
  tag severity: 'medium'
  tag gid: 'V-258756'
  tag rid: 'SV-258756r933329_rule'
  tag stig_id: 'ESXI-80-000195'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-62405r933328_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
