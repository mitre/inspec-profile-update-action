control 'SV-258778' do
  title 'The ESXi host must not suppress warnings about unmitigated hyperthreading vulnerabilities.'
  desc 'The L1 Terminal Fault (L1TF) CPU vulnerabilities published in 2018 have patches and mitigations available in vSphere. However, there are performance impacts to these mitigations that require careful thought and planning from the system administrator before implementation. Until a mitigation is implemented, the UI warning about the lack of a mitigation must not be dismissed so the system administrator does not assume the vulnerability has been addressed.'
  desc 'check', 'From the vSphere Client go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "UserVars.SuppressHyperthreadWarning" value and verify it is set to "0".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning

If the "UserVars.SuppressHyperthreadWarning" setting is not set to "0", this is a finding.'
  desc 'fix', 'From the vSphere Client go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "UserVars.SuppressHyperthreadWarning" value and configure it to "0".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressHyperthreadWarning | Set-AdvancedSetting -Value 0'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 ESXi'
  tag check_id: 'C-62518r933393_chk'
  tag severity: 'medium'
  tag gid: 'V-258778'
  tag rid: 'SV-258778r933395_rule'
  tag stig_id: 'ESXI-80-000223'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-62427r933394_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
