control 'SV-78265' do
  title 'The VMM must automatically terminate a user session after inactivity timeouts have expired or at shutdown by setting an idle timeout on shell services.'
  desc 'When the ESXi Shell or SSH services are enabled on a host they will run indefinitely.  To avoid having these services left running set the ESXiShellTimeOut.  The ESXiShellTimeOut defines a window of time after which the ESXi Shell and SSH services will automatically be terminated.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the UserVars.ESXiShellTimeOut value and verify it is set to 600 (10 Minutes).

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut

If the UserVars.ESXiShellTimeOut setting is not set to 600, this is a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the UserVars.ESXiShellTimeOut value and configure it to 600.

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name UserVars.ESXiShellTimeOut | Set-AdvancedSetting -Value 600'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64525r1_chk'
  tag severity: 'medium'
  tag gid: 'V-63775'
  tag rid: 'SV-78265r1_rule'
  tag stig_id: 'ESXI-06-100042'
  tag gtitle: 'SRG-OS-000279-VMM-001010'
  tag fix_id: 'F-69703r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
