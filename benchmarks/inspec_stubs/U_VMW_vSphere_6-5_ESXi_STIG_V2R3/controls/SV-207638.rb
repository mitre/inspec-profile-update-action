control 'SV-207638' do
  title 'The ESXi host must use Active Directory for local user authentication.'
  desc 'Join ESXi hosts to an Active Directory (AD) domain to eliminate the need to create and maintain multiple local user accounts. Using AD for user authentication simplifies the ESXi host configuration, ensures password complexity and reuse policies are enforced and reduces the risk of security breaches and unauthorized access.  Note: If the AD group "ESX Admins" (default) exists then all users and groups that are assigned as members to this group will have full administrative access to all ESXi hosts the domain.'
  desc 'check', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Authentication Services.  Verify the Directory Services Type is set to Active Directory.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-VMHostAuthentication

For systems that do not use Active Directory and have no local user accounts, other than root and/or vpxuser, this is not applicable.

For systems that do not use Active Directory and do have local user accounts, other than root and/or vpxuser, this is a finding.

If the Directory Services Type is not set to "Active Directory", this is a finding.'
  desc 'fix', 'From the vSphere Web Client select the ESXi Host and go to Configure >> System >> Authentication Services. Click Join Domain and enter the AD domain to join, select the "Using credentials” radio button and enter the credentials of an account with permissions to join machines to AD (use UPN naming – user@domain) and then click OK.

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-VMHostAuthentication | Set-VMHostAuthentication -JoinDomain -Domain "domain name" -User "username" -Password "password"'
  impact 0.3
  ref 'DPMS Target VMware vSphere 6.5 ESXi'
  tag check_id: 'C-7893r364313_chk'
  tag severity: 'low'
  tag gid: 'V-207638'
  tag rid: 'SV-207638r378847_rule'
  tag stig_id: 'ESXI-65-000037'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag fix_id: 'F-7893r364314_fix'
  tag 'documentable'
  tag legacy: ['V-94021', 'SV-104107']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
