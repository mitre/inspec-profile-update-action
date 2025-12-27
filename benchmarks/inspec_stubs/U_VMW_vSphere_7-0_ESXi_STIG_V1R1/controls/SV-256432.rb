control 'SV-256432' do
  title 'The ESXi host must not suppress warnings that the local or remote shell sessions are enabled.'
  desc 'Warnings that local or remote shell sessions are enabled alert administrators to activity they may not be aware of and need to investigate.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.SuppressShellWarning" value and verify it is set to "0".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning

If the "UserVars.SuppressShellWarning" setting is not set to "0" or the setting does not exist, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.SuppressShellWarning" value and set it to "0".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Set-AdvancedSetting -Value "0"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60107r886075_chk'
  tag severity: 'medium'
  tag gid: 'V-256432'
  tag rid: 'SV-256432r886077_rule'
  tag stig_id: 'ESXI-70-000079'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-60050r886076_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
