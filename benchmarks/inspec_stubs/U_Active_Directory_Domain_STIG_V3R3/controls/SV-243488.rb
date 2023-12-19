control 'SV-243488' do
  title 'User accounts with delegated authority must be removed from Windows built-in administrative groups or remove the delegated authority from the accounts.'
  desc 'In AD it is possible to delegate account and other AD object ownership and administration tasks. (This is commonly done for help desk or other user support staff.) This is done to avoid the need to assign users to Windows groups with more widely ranging privileges. If a user with delegated authority to user accounts in a specific OU is also a member of the Administrators group, that user has the ability to reconfigure a wide range of domain security settings and change user accounts outside of the OU to which s/he is a delegated authority. A lack of specific baseline documentation of accounts with delegated privileges makes it impossible to determine if the configured privileges are consistent with the intended security policy.'
  desc 'check', '1. Interview the IAM or site representative and obtain the list of accounts that have been delegated AD object ownership or update permissions and that are not members of Windows built-in administrative groups.
(This includes accounts for help desk or support personnel who are not Administrators, but have authority in AD to maintain user accounts or printers.)

2. If accounts with delegated authority are defined and there is no list, then this is a finding.

3. Count the number of accounts on the list.

4. If the number of accounts with delegated authority is greater than 10, review the site documentation that justifies this number.  Validate that the IAM explicitly acknowledges the need to have a high number of privileged users.

5. If the number of accounts with delegated authority is greater than 10 and there is no statement in the documentation that justifies the number, then this is a finding.'
  desc 'fix', '1. Remove user accounts with delegated authority from Windows built-in administrative groups or remove the delegated authority from the accounts. 

2. Document all user accounts with delegated AD object ownership or update authority. 

3. Annotate the account list with a statement such as, "The high number of privileged accounts is required to address site operational requirements."

4. Reduce the number of user accounts with delegated AD object ownership or update authority.'
  impact 0.3
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46763r723497_chk'
  tag severity: 'low'
  tag gid: 'V-243488'
  tag rid: 'SV-243488r723555_rule'
  tag stig_id: 'AD.0260'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46720r723554_fix'
  tag 'documentable'
  tag legacy: ['V-8521', 'SV-9018']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
