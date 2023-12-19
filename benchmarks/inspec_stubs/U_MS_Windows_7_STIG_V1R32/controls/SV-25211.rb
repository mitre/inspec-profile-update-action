control 'SV-25211' do
  title 'System mechanisms must be implemented to enforce automatic expiration of passwords.'
  desc 'Passwords that do not expire increase exposure with a greater probability of being discovered or cracked.'
  desc 'check', 'Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry.

UserName
SID
PswdExpires
AcctDisabled
Groups

If any accounts have "No" in the "PswdExpires" column, this is a finding.

The following are exempt from this requirement:
Built-in Administrator Account
Application Accounts

Accounts that meet the requirements for allowable exceptions must be documented with the ISSO.'
  desc 'fix', 'Configure all passwords to expire.  Ensure "Password never expires" is not checked on all accounts in Computer Management, Local Users and Groups.  Document any exceptions with the ISSO.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62081r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6840'
  tag rid: 'SV-25211r2_rule'
  tag gtitle: 'Password Expiration'
  tag fix_id: 'F-66979r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
