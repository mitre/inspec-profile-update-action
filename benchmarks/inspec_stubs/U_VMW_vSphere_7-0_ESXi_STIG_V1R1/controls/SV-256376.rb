control 'SV-256376' do
  title 'The ESXi host must verify the DCUI.Access list.'
  desc 'Lockdown mode disables direct host access, requiring that administrators manage hosts from vCenter Server. However, if a host becomes isolated from vCenter, the administrator is locked out and can no longer manage the host. 

The "DCUI.Access" advanced setting allows specified users to exit lockdown mode in such a scenario. If the Direct Console User Interface (DCUI) is running in strict lockdown mode, this setting is ineffective.'
  desc 'check', 'For environments that do not use vCenter server to manage ESXi, this is not applicable.

From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Select the "DCUI.Access" value and verify only the root user is listed.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name DCUI.Access and verify it is set to root.

If the "DCUI.Access" is not restricted to "root", this is a finding.

Note: This list is only for local user accounts and should only contain the root user.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Advanced System Settings.

Click "Edit". Select the "DCUI.Access" value and configure it to "root".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Get-AdvancedSetting -Name DCUI.Access | Set-AdvancedSetting -Value "root"'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60051r885907_chk'
  tag severity: 'medium'
  tag gid: 'V-256376'
  tag rid: 'SV-256376r885909_rule'
  tag stig_id: 'ESXI-70-000002'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-59994r885908_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
