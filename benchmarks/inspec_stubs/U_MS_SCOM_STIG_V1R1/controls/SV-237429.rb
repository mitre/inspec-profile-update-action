control 'SV-237429' do
  title 'The Microsoft SCOM Service Accounts and Run As accounts must not be granted enterprise or domain level administrative privileges.'
  desc 'The Microsoft SCOM privileged Run As accounts are used to execute work flow tasks on target endpoints. A SCOM Run As account must only have the level of privileges required to perform the defined SCOM actions. An account with full administrative at the domain or enterprise level could be used to breach security boundaries and compromise the endpoint.'
  desc 'check', 'Obtain the User ID(s) for the appropriate accounts in SCOM:

Open the Operations Console and select the Administration workspace.

Under Run As Configuration, select Accounts.

Double-click on each account listed under the Windows type and select the credentials tab (note that the network system and local system accounts do not need to be checked). Note the Username and domain name. Open Active Directory Users and Computers.

Determine rights in Active Directory:

Review the Domain Admins, Administrators (in AD), Enterprise Admins, Schema Admins groups, and any group that is a member of these groups.

If a SCOM Run-As account or Service account is a member of any of these groups, this is a finding.'
  desc 'fix', 'Remove the service accounts from these groups and grant appropriate permissions to them. SCOM service account permission documentation can be found at this link: https://kevinholman.com/2019/03/08/scom-2016-security-account-matrix/. Run As accounts that are not being used as SCOM service accounts should be configured to least privileges as well.'
  impact 0.7
  ref 'DPMS Target Microsoft SCOM'
  tag check_id: 'C-40648r643931_chk'
  tag severity: 'high'
  tag gid: 'V-237429'
  tag rid: 'SV-237429r643933_rule'
  tag stig_id: 'SCOM-AC-000007'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-40611r643932_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
