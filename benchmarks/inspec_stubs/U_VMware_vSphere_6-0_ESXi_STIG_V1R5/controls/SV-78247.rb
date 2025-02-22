control 'SV-78247' do
  title 'The VMM must require individuals to be authenticated with an individual authenticator prior to using a group authenticator by using the vSphere Authentication Proxy.'
  desc 'If you configure your host to join an Active Directory domain using Host Profiles the Active Directory credentials are saved in the host profile and are transmitted over the network. To avoid having to save Active Directory credentials in the Host Profile and to avoid transmitting Active Directory credentials over the network use the vSphere Authentication Proxy.'
  desc 'check', 'From the vSphere Client go to Home >> Host Profiles.

Select a Host Profile to edit.  

View the settings under Authentication Configuration >> Active Directory Configuration >> JoinDomain Method.

Verify the method used to join hosts to a domain is set to "Use vSphere Authentication Proxy to add the host to domain".

or

From a PowerCLI command prompt while connected to vCenter run the following command:

Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}

Verify if "JoinADEnabled" is "True" then "JoinDomainMethod" should be "FixedCAMConfigOption".

For systems that do not use Active Directory and have no local user accounts, other than root, dcui, and/or vpxuser, this is Not Applicable.

For systems that do not use Active Directory and do have local user accounts, other than root, dcui, and/or vpxuser, this is a finding.

If vSphere Authentication Proxy is not used to join hosts to an Active Directory domain, this is a finding.'
  desc 'fix', 'When using host profiles do the following:

From the vSphere Client, go to Home >> Host Profiles.

Select a Host Profile to edit.  

View the settings under Authentication Configuration >> Active Directory Configuration >> JoinDomain Method.  

Set the method used to join hosts to a domain to "Use vSphere Authentication Proxy to add the host to domain".

Provide the IP address of the vSphere Authentication Proxy server.

To join a host to Active Directory manually without host profiles do the following:

From the vSphere Client, select the ESXi Host and go to Configuration >> Authentication Services.  

Click "Properties".

Change the "Directory Service Type" to "Active Directory".

Enter the domain to join.

Check "Use vSphere Authentication Proxy".

Enter the proxy server address.

Click "Join Domain".'
  impact 0.5
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64507r3_chk'
  tag severity: 'medium'
  tag gid: 'V-63757'
  tag rid: 'SV-78247r2_rule'
  tag stig_id: 'ESXI-06-100038'
  tag gtitle: 'SRG-OS-000109-VMM-000550'
  tag fix_id: 'F-69685r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
