control 'SV-29482' do
  title 'Outdated or unused accounts must be removed from the system or disabled.'
  desc 'Outdated or unused accounts provide penetration points that may go undetected.  Inactive accounts must be deleted if no longer necessary or, if still required, disabled until needed.'
  desc 'check', 'Open a "Command Prompt" with elevated privileges. (Run as administrator)

Domain Controllers:

Enter "Dsquery user -limit 0 -inactive 5 -o rdn".
A list of user accounts that have been inactive for 5 weeks will be displayed.

Disabled Accounts can be determined by using the following:
Enter "Dsquery user -limit 0 -disabled -o rdn".

Exclude the following accounts:
Built-in administrator account
Built-in guest account
Application accounts

If any enabled accounts have not been logged on to within the past 35 days, this is a finding.

Member servers and standalone systems:

Verify the "Last logon" for each enabled local account on the system.  Enter "Net User" to view a list of accounts.

For each account enter "Net User [account name]", where [account name] is the name of the account to be reviewed.

Exclude the following accounts:
Built-in administrator account
Built-in guest account
Application accounts

If "Account active" is "Yes" and the "Last logon" date is more than 35 days old for any accounts, this is a finding.

Inactive accounts that have been reviewed and deemed to be required must be documented with the ISSO.

Note: Other queries or tools may be used. The organization must be able to demonstrate the results are valid and meet the intent of the requirement.'
  desc 'fix', 'Regularly review accounts to determine if they are still active.  Remove or disable accounts that have not been used in the last 35 days.'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-79563r1_chk'
  tag severity: 'low'
  tag gid: 'V-1112'
  tag rid: 'SV-29482r3_rule'
  tag gtitle: 'Dormant Accounts'
  tag fix_id: 'F-74863r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
