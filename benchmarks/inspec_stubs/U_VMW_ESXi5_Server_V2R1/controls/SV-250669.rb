control 'SV-250669' do
  title 'The system must use Active Directory for local user authentication for accounts other than root and the vpxuser.'
  desc 'Creating local user accounts on each host presents challenges with having to synchronize account names and passwords across multiple hosts. Join ESXi hosts to an Active Directory domain to eliminate the need to create and maintain local user accounts. Using Active Directory for user authentication simplifies the ESXi host configuration and reduces the risk for configuration issues that could lead to unauthorized access. Note that when adding ESXi hosts to Active Directory, if the group "ESX Admins" exists, all user/group accounts assigned to the group will have full administrative access to the host.'
  desc 'check', 'For systems that do not use Active Directory and have no local user accounts, other than root and/or vpxuser, this check is not applicable.

For systems that do not use Active Directory and do have local user accounts, other than root and/or vpxuser, this check is a finding.

From the vSphere client, select the host, then "Configuration >> Authentication Services" and verify the Directory Services Type is set to Active Directory.

If the Directory Services Type is not set to "Active Directory", this is a finding.'
  desc 'fix', 'Perform the following steps to configure the ESXi host to use Active Directory: 
(1) Log into the ESXi host using the vSphere Client and authenticating with the root account (or an equivalent account). 
(2) Select the ESXi host from the inventory and click the Configuration tab. 
(3) From the Software section, select Authentication Services. 
(4) Click Properties in the upper-right corner. 
(5) From the Directory Services Configuration dialog box, select Active Directory from the Select Directory Service Type drop-down list. 
(6) Supply the DNS domain name of the Active Directory domain this ESXi host will use for authentication. 
(7) Click the Join Domain button. 
(8) Specify a username and password that has permission to allow the host to join the domain.

Once the ESXi host is joined to Active Directory, users will be able to authenticate to an ESXi host using their Active Directory credentials. Using the vSphere Client or the vCLI, users can use either the domain\\username or username@domain syntax.'
  impact 0.3
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54104r799004_chk'
  tag severity: 'low'
  tag gid: 'V-250669'
  tag rid: 'SV-250669r799006_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000154'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54058r799005_fix'
  tag 'documentable'
  tag legacy: ['V-39348', 'SV-51206']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
