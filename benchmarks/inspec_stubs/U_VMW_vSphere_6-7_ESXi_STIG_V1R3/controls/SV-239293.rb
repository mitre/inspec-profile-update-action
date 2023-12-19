control 'SV-239293' do
  title 'ESXi hosts using Host Profiles and/or Auto Deploy must use the vSphere Authentication Proxy to protect passwords when adding themselves to Active Directory.'
  desc 'If a host is configured to join an Active Directory domain using Host Profiles and/or Auto Deploy, the Active Directory credentials are saved in the profile and are transmitted over the network. To avoid having to save Active Directory credentials in the Host Profile and to avoid transmitting Active Directory credentials over the network, use the vSphere Authentication Proxy.

'
  desc 'check', 'From the vSphere Client, go to Home >> Host Profiles and select a Host Profile to edit. 

View the settings under Security and Services >> Security Settings >> Authentication Configuration >> Active Directory Configuration >> Join Domain Method. 

Verify the method used to join hosts to a domain is set to "Use vSphere Authentication Proxy to add the host to domain".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following command:

Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}

Verify that if "JoinADEnabled" is "True", "JoinDomainMethod" is "FixedCAMConfigOption".

If not using Host Profiles to join active directory, this is not a finding.'
  desc 'fix', 'From the vSphere Client, go to Home >> Host Profiles and select a Host Profile to edit. 

View the settings under Security and Services >> Security Settings >> Authentication Configuration >> Active Directory Configuration >> Join Domain Method. 

Set the method used to join hosts to a domain to "Use vSphere Authentication Proxy to add the host to domain" and provide the IP address of the vSphere Authentication Proxy server.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 ESXi'
  tag check_id: 'C-42526r816571_chk'
  tag severity: 'medium'
  tag gid: 'V-239293'
  tag rid: 'SV-239293r854590_rule'
  tag stig_id: 'ESXI-67-000038'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag fix_id: 'F-42485r674807_fix'
  tag satisfies: ['SRG-OS-000104-VMM-000500', 'SRG-OS-000109-VMM-000550', 'SRG-OS-000112-VMM-000560', 'SRG-OS-000113-VMM-000570']
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-000770', 'CCI-001941', 'CCI-001942']
  tag nist: ['IA-2', 'IA-2 (5)', 'IA-2 (8)', 'IA-2 (9)']
end
