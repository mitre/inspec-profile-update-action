control 'SV-256403' do
  title 'ESXi hosts using Host Profiles and/or Auto Deploy must use the vSphere Authentication Proxy to protect passwords when adding themselves to Active Directory.'
  desc 'If a host is configured to join an Active Directory domain using Host Profiles and/or Auto Deploy, the Active Directory credentials are saved in the profile and are transmitted over the network. 

To avoid having to save Active Directory credentials in the Host Profile and to avoid transmitting Active Directory credentials over the network, use the vSphere Authentication Proxy.'
  desc 'check', 'If the organization is not using Host Profiles to join Active Directory, this is not applicable.

From the vSphere Client, go to Home >> Policies and Profiles >> Host Profiles.

Click a Host Profile >> Configure >> Security and Services >> Security Settings >> Authentication Configuration >> Active Directory Configuration >> Join Domain Method.

If the method used to join hosts to a domain is not set to "Use vSphere Authentication Proxy to add the host to domain", this is a finding.

or

From a PowerCLI command prompt while connected to vCenter, run the following command:

Get-VMHost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}

If "JoinADEnabled" is "True" and "JoinDomainMethod" is not "FixedCAMConfigOption", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Home >> Policies and Profiles >> Host Profiles.

Click a Host Profile >> Configure >> Security and Services >> Security Settings >> Authentication Configuration >> Active Directory Configuration.

Click "Edit Host Profile...". Set the "Join Domain Method" to "Use vSphere Authentication Proxy to add the host to domain" and provide the IP address of the vSphere Authentication Proxy server. 

Click "Save".'
  impact 0.5
  ref 'DPMS Target VMware vSphere 7.0 ESXi'
  tag check_id: 'C-60078r885988_chk'
  tag severity: 'medium'
  tag gid: 'V-256403'
  tag rid: 'SV-256403r885990_rule'
  tag stig_id: 'ESXI-70-000038'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag fix_id: 'F-60021r885989_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
