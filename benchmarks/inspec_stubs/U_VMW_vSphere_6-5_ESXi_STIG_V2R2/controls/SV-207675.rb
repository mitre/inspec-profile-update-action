control 'SV-207675' do
  title 'The ESXi host must require individuals to be authenticated with an individual authenticator prior to using a group authenticator by using Active Directory for local user authentication.'
  desc 'Join ESXi hosts to an Active Directory (AD) domain to eliminate the need to create and maintain multiple local user accounts. Using AD for user authentication simplifies the ESXi host configuration, ensures password complexity and reuse policies are enforced and reduces the risk of security breaches and unauthorized access.  Note: If the AD group "ESX Admins" (default) exists then all users and groups that are assigned as members to this group will have full administrative access to all ESXi hosts the domain.'
  desc 'check', 'For systems that do not use Active Directory and have no local user accounts, other than "root" and/or "vpxuser", this is not applicable.

From the vSphere Client select the ESXi host and go to Configuration >> Authentication Services. Verify the "Directory Services Type" is set to "Active Directory".

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-VMHostAuthentication

For systems that do not use Active Directory and do have local user accounts, other than "root" and/or "vpxuser"", this is a finding.

If the "Directory Services Type" is not set to "Active Directory", this is a finding.
If you are not using Host Profiles to join active directory, this is not a finding.'
  desc 'fix', 'From the vSphere Client select the ESXi host and go to Configuration >> Authentication Services.  Click "Properties" and change the "Directory Service Type" to "Active Directory", enter the domain to join, check "Use vSphere Authentication Proxy" and enter the proxy server address then click "Join Domain".

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-VMHostAuthentication | Set-VMHostAuthentication -JoinDomain -Domain "domain name" -User "username" -Password "password"'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7930r364424_chk'
  tag severity: 'low'
  tag gid: 'V-207675'
  tag rid: 'SV-207675r378862_rule'
  tag stig_id: 'ESXI-65-100037'
  tag gtitle: 'SRG-OS-000109-VMM-000550'
  tag fix_id: 'F-7930r364425_fix'
  tag 'documentable'
  tag legacy: ['V-94505', 'SV-104335']
  tag cci: ['CCI-000770']
  tag nist: ['IA-2 (5)']
end
