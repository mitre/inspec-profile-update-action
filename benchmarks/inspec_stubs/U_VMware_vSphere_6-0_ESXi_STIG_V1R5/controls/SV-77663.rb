control 'SV-77663' do
  title 'The system must verify the DCUI.Access list.'
  desc 'Lockdown mode disables direct host access requiring that admins manage hosts from vCenter Server.  However, if a host becomes isolated from vCenter Server, the admin is locked out and can no longer manage the host. If you are using normal lockdown mode, you can avoid becoming locked out of an ESXi host that is running in lockdown mode, by setting DCUI.Access to a list of highly trusted users who can override lockdown mode and access the DCUI. The DCUI is not running in strict lockdown mode.'
  desc 'check', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the DCUI.Access value and verify only the root user is listed.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name DCUI.Access and verify it is set to root.

If the DCUI.Access is not restricted to root, this is a finding.

Note: This list is only for local user accounts and should only contain the root user.'
  desc 'fix', 'From the vSphere Client select the ESXi Host and go to Configuration >> Advanced Settings.  Select the DCUI.Access value and configure it to root.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name DCUI.Access | Set-AdvancedSetting -Value "root"'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63907r1_chk'
  tag severity: 'low'
  tag gid: 'V-63173'
  tag rid: 'SV-77663r1_rule'
  tag stig_id: 'ESXI-06-000002'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-69091r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
