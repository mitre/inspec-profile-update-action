control 'SV-239259' do
  title 'The ESXi host must verify the DCUI.Access list.'
  desc 'Lockdown mode disables direct host access, requiring that administrators manage hosts from vCenter Server. However, if a host becomes isolated from vCenter Server, the administrator is locked out and can no longer manage the host. If using normal Lockdown Mode, avoid becoming locked out of an ESXi host that is running in Lockdown Mode by setting DCUI.Access to a list of highly trusted users who can override Lockdown Mode and access the DCUI. The DCUI is not running in strict Lockdown Mode.'
  desc 'check', 'For environments that do not use vCenter server to manage ESXi, this is Not Applicable.

From the vSphere Client, select the ESXi host and go to Configure >> System >> Advanced System Settings. 

Select the "DCUI.Access" value and verify that only the root user is listed.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name DCUI.Access and verify it is set to root.

If the DCUI.Access is not restricted to root, this is a finding.

Note: This list is only for local user accounts and should only contain the root user.'
  desc 'fix', 'From the vSphere Client, select the ESXi host and go to Configure >> System >> Advanced System Settings.

Click "Edit", select the "DCUI.Access" value, and configure it to root.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name DCUI.Access | Set-AdvancedSetting -Value "root"'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42492r674704_chk'
  tag severity: 'low'
  tag gid: 'V-239259'
  tag rid: 'SV-239259r674706_rule'
  tag stig_id: 'ESXI-67-000002'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-42451r674705_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
