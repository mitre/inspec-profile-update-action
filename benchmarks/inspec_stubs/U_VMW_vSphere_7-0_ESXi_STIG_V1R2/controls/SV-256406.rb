control 'SV-256406' do
  title 'The ESXi host must terminate shell services after 10 minutes.'
  desc 'When the ESXi Shell or Secure Shell (SSH) services are enabled on a host, they will run indefinitely. To avoid having these services left running, set the "ESXiShellTimeOut". The "ESXiShellTimeOut" defines a window of time after which the ESXi Shell and SSH services will be stopped automatically.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.ESXiShellTimeOut" value and verify it is set to "600" (10 minutes).

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut

If the "UserVars.ESXiShellTimeOut" setting is not set to "600", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "UserVars.ESXiShellTimeOut" value and configure it to "600".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60081r885997_chk'
  tag severity: 'medium'
  tag gid: 'V-256406'
  tag rid: 'SV-256406r885999_rule'
  tag stig_id: 'ESXI-70-000042'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-60024r885998_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
