control 'SV-250670' do
  title 'Active Directory ESX Admin group membership must be verified unused.'
  desc 'When adding ESXi hosts to Active Directory, if the group "ESX Admins" exists, all user/group accounts assigned to the group will have full administrative access to the host. Discretion should be used when managing membership to the "ESX Admins" group.'
  desc 'check', 'For systems that do not use Active Directory and have no local user accounts, other than root and/or vpxuser, this check is not applicable.

For systems that do not use Active Directory and do have local user accounts, other than root and/or vpxuser, this check is a finding.

From the vSphere Client/vCenter, select the host, then Configuration >> Software/Advanced Settings >> HostAgent.

Verify "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" is not set to "ESX Admins".

If the "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" keyword is set to "ESX Admins", this is a finding.'
  desc 'fix', 'From the vSphere Client/vCenter, select the host, then Configuration >> Software/Advanced Settings >> HostAgent.

Change the "Config.HostAgent.plugins.hostsvc.esxAdminsGroup" to a pre-defined group other than the default "ESX Admins".

Note: The new administrator group must have been previously defined on the Active Directory server.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54105r799007_chk'
  tag severity: 'low'
  tag gid: 'V-250670'
  tag rid: 'SV-250670r799009_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000155'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54059r799008_fix'
  tag 'documentable'
  tag legacy: ['SV-51207', 'V-39349']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
