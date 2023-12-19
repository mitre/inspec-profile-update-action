control 'SV-207639' do
  title 'The ESXi host must use the vSphere Authentication Proxy to protect passwords when adding ESXi hosts to Active Directory.'
  desc 'If you configure your host to join an Active Directory domain using Host Profiles the Active Directory credentials are saved in the host profile and are transmitted over the network. To avoid having to save Active Directory credentials in the Host Profile and to avoid transmitting Active Directory credentials over the network use the vSphere Authentication Proxy.'
  desc 'check', 'From the vSphere Web Client go to Home >> Host Profiles >> and select a Host Profile to edit. View the settings under Security and Services >> Security Settings >> Authentication Configuration >> Active Directory Configuration >> Join Domain Method. Verify the method used to join hosts to a domain is set to "Use vSphere Authentication Proxy to add the host to domain".

or

From a PowerCLI command prompt while connected to vCenter run the following command:

Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}

Verify if JoinADEnabled is True then JoinDomainMethod should be "FixedCAMConfigOption".

If you are not using Host Profiles to join active directory, this is not a finding.'
  desc 'fix', 'From the vSphere Web Client go to Home >> Host Profiles >> and select a Host Profile to edit. View the settings under Security and Services >> Security Settings >> Authentication Configuration >> Active Directory Configuration >> Join Domain Method. Set the method used to join hosts to a domain to "Use vSphere Authentication Proxy to add the host to domain" and provide the IP address of the vSphere Authentication Proxy server.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7894r364316_chk'
  tag severity: 'medium'
  tag gid: 'V-207639'
  tag rid: 'SV-207639r378847_rule'
  tag stig_id: 'ESXI-65-000038'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag fix_id: 'F-7894r364317_fix'
  tag 'documentable'
  tag legacy: ['SV-104109', 'V-94023']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
