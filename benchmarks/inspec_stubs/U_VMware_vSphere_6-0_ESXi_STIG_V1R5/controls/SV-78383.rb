control 'SV-78383' do
  title 'The VMM must implement replay-resistant authentication mechanisms for network access to privileged accounts by using Active Directory for local user authentication.'
  desc 'Join ESXi hosts to an Active Directory (AD) domain to eliminate the need to create and maintain multiple local user accounts. Using AD for user authentication simplifies the ESXi host configuration, ensures password complexity and reuse policies are enforced and reduces the risk of security breaches and unauthorized access.  Note: If the AD group "ESX Admins" (default) exists then all users and groups that are assigned as members to this group will have full administrative access to all ESXi hosts the domain.'
  desc 'check', 'From the vSphere Client, select the ESXi Host and go to Configuration >> Authentication Services.  

Verify the "Directory Services Type" is set to "Active Directory".

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-VMHostAuthentication

For systems that do not use Active Directory and have no local user accounts, other than root, dcui, and/or vpxuser, this is Not Applicable.

For systems that do not use Active Directory and do have local user accounts, other than root, dcui, and/or vpxuser, this is a finding.

If the "Directory Services Type" is not set to "Active Directory", this is a finding.'
  desc 'fix', 'From the vSphere Client, select the ESXi Host and go to Configuration >> Authentication Services.  

Click "Properties". 

Change the "Directory Service Type" to "Active Directory".

Enter the domain to join.

Check "Use vSphere Authentication Proxy".

Enter the proxy server address.

Click "Join Domain".

or

From a PowerCLI command prompt while connected to the ESXi host run the following command:

Get-VMHost | Get-VMHostAuthentication | Set-VMHostAuthentication -JoinDomain -Domain "domain name" -User "username" -Password "password"'
  impact 0.3
  ref 'DPMS Target ESXi 6.0'
  tag check_id: 'C-64643r2_chk'
  tag severity: 'low'
  tag gid: 'V-63893'
  tag rid: 'SV-78383r2_rule'
  tag stig_id: 'ESXI-06-200037'
  tag gtitle: 'SRG-OS-000112-VMM-000560'
  tag fix_id: 'F-69821r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
