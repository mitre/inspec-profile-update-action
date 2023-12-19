control 'SV-237427' do
  title 'The Microsoft SCOM Run As accounts must only use least access permissions.'
  desc 'The Microsoft SCOM privileged Run As accounts are used to execute work flow tasks on target endpoints. Run As Accounts are interactive logon sessions on a system. An attacker who has compromised one of those systems could potentially reuse the credentials of a Run As account on another system.'
  desc 'check', 'Obtain the User ID(s) in SCOM:

Open the Operations Console and select the Administration workspace.

Under Run As Configuration, select Accounts. 

Double-click on each account listed under the Windows type and select the credentials tab (note that the network system and local system accounts do not need to be checked). Note the Username and domain name. Click on the Distribution tab and note the computer names that the account is distributed to.

Validate Permissions in Active Directory:

For each SCOM Run As account, open the Active Directory Users and Computers MMC and if necessary connect to the appropriate domain. Right-click on the domain and select "Find". In the "Name" field, type the User ID and click "Find Now". The account will appear in the results below. Double-click on the account and select the "Member Of" tab.

Review the groups listed. If any group listed is an administrator on any system other than the systems the account is distributed to, this is a finding.

If the account is part of Domain Administrators or Enterprise Administrators, elevate to CAT I.'
  desc 'fix', 'Create an active directory group in which the account is a member. Assign this group the appropriate permissions on only the servers that need this account. Remove the Run As account from all additional administrative AD groups.'
  impact 0.5
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40646r643925_chk'
  tag severity: 'medium'
  tag gid: 'V-237427'
  tag rid: 'SV-237427r643927_rule'
  tag stig_id: 'SCOM-AC-000005'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-40609r643926_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
