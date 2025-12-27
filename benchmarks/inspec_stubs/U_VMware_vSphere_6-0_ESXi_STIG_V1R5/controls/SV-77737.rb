control 'SV-77737' do
  title 'Active Directory ESX Admin group membership must not be used.'
  desc 'When adding ESXi hosts to Active Directory, if the group "ESX Admins" exists, all user/group accounts assigned to the group will have full administrative access to the host. Discretion should be used when managing membership to the "ESX Admins" group.'
  desc 'check', 'From the vSphere Client, select the ESXi Host and go to Configuration >> Advanced Settings.  

Select the "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" value. 

Verify it is not set to "ESX Admins".

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup

For systems that do not use Active Directory and have no local user accounts, other than root, dcui, and/or vpxuser, this is Not Applicable.

For systems that do not use Active Directory and do have local user accounts, other than root, dcui, and/or vpxuser, this is a finding.

If the "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" keyword is set to "ESX Admins", this is a finding.'
  desc 'fix', 'From the vSphere Client, select the ESXi Host and go to Configuration >> Advanced Settings.  

Select the "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" value.

Configure it to an Active Directory group other than "ESX Admins".

or

From a PowerCLI command prompt while connected to the ESXi host run the following commands:

Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.plugins.hostsvc.esxAdminsGroup | Set-AdvancedSetting -Value <AD Group>'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-63981r3_chk'
  tag severity: 'low'
  tag gid: 'V-63247'
  tag rid: 'SV-77737r2_rule'
  tag stig_id: 'ESXI-06-000039'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag fix_id: 'F-69165r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
