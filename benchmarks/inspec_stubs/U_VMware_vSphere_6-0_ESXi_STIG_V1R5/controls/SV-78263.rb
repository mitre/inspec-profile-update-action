control 'SV-78263' do
  title 'The VMM must automatically terminate a user session after inactivity timeouts have expired or at shutdown by setting an idle timeout.'
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
  tag check_id: 'C-64523r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63773'
  tag rid: 'SV-78263r1_rule'
  tag stig_id: 'ESXI-06-100041'
  tag gtitle: 'SRG-OS-000279-VMM-001010'
  tag fix_id: 'F-69701r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
