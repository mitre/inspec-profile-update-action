control 'SV-29395' do
  title 'To the extent system capabilities permit, system mechanisms are not implemented to enforce automatic expiration of passwords and to prevent reuse.'
  desc 'Passwords that do not expire or are reused increase the exposure of a password with greater probability of being discovered or cracked.'
  desc 'check', 'Using the DUMPSEC utility:

Select “Dump Users as Table” from the “Report” menu.
Select the available fields in the following sequence, and click on the “Add” button for each entry:

UserName
SID
PswdRequired
PswdExpires
PswdLastSetTime
LastLogonTime
AcctDisabled
Groups

If any accounts listed in the user report have a “No” in the “PswdExpires” column, then this is a finding. 

Note: The following command can be used on Windows 2003/2008 Active Directory if DumpSec cannot be run:

Open a Command Prompt.
Enter “Dsquery user -limit 0 | Dsget user -dn -pwdneverexpires”.
This will return a list of User Accounts with Yes/No for Pwdneverexpires.

If any accounts have "Yes", then this is a finding.
The results can be directed to a text file by adding “> filename.txt” at the end of the command

The following are exempt from this requirement:
Built-in Administrator Account
Application Accounts

Documentable Explanation: Accounts that meet the requirements for allowable exceptions should be documented with the IAO.'
  desc 'fix', 'Configure all information systems to expire passwords.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-3230r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6840'
  tag rid: 'SV-29395r1_rule'
  tag gtitle: 'Password Expiration'
  tag fix_id: 'F-6527r1_fix'
  tag false_positives: 'The following accounts are exempt from this check.
     Built-in Administrator Account
     Application accounts'
  tag potential_impacts: 'Enforcing passwords to be changed at regular intervals may invite users to write down the passwords each time they are required to make a change. Ensure that all users store passwords in a secured location.'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
