control 'SV-77741' do
  title 'The system must set a timeout to automatically disable idle sessions after a predetermined period.'
  desc 'If a user forgets to log out of their SSH session, the idle connection will remains open indefinitely, increasing the potential for someone to gain privileged access to the host.  The ESXiShellInteractiveTimeOut allows you to automatically terminate idle shell sessions.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the UserVars.ESXiShellInteractiveTimeOut value and verify it is set to 600 (10 Minutes).

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut

If the UserVars.ESXiShellInteractiveTimeOut setting is not set to 600, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the UserVars.ESXiShellInteractiveTimeOut value and configure it to 600.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellInteractiveTimeOut | Set-AdvancedSetting -Value 600'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63985r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63251'
  tag rid: 'SV-77741r1_rule'
  tag stig_id: 'ESXI-06-000041'
  tag gtitle: 'SRG-OS-000163-VMM-000700'
  tag fix_id: 'F-69169r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
