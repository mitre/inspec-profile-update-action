control 'SV-258777' do
  title 'The ESXi host must not suppress warnings that the local or remote shell sessions are enabled.'
  desc 'Warnings that local or remote shell sessions are enabled alert administrators to activity they may not be aware of and need to investigate.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.SuppressShellWarning" value and verify it is set to "0".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning

If the "UserVars.SuppressShellWarning" setting is not set to "0", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "UserVars.SuppressShellWarning" value and configure it to "0".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Set-AdvancedSetting -Value 0'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62517r933390_chk'
  tag severity: 'medium'
  tag gid: 'V-258777'
  tag rid: 'SV-258777r933392_rule'
  tag stig_id: 'ESXI-80-000222'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62426r933391_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
