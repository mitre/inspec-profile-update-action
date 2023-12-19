control 'SV-29334' do
  title 'Application account passwords length and change requirement'
  desc 'Setting application accounts to expire may cause applications to stop functioning. The site will have a policy that application account passwords manually generated and entered by a system administrator are changed at least annually or when a system administrator with knowledge of the password leaves the organization. Application/service account passwords will be at least 15 characters and follow complexity requirements for all passwords.'
  desc 'check', 'The site should have a local policy to ensure that passwords for application/service accounts are at least 15 characters in length and meet complexity requirements for all passwords. Application/service account passwords manually generated and entered by a system administrator must be changed at least annually or whenever a system administrator that has knowledge of the password leaves the organization.

Interview the system administrators on their policy for application/service accounts.  If it does not meet the above requirements, this is a finding.

Using the DUMPSEC utility:

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

If any application accounts listed in the Dumpsec user report have a date older than one year in the “PwsdLastSetTime” column, then this is a finding. 

Note: The following command can be used on Windows 2003/2008 Active Directory if DumpSec cannot be run:

Open a Command Prompt.
Enter “Dsquery user -limit 0 -o rdn -stalepwd 365”.
This will return a list of User Accounts with passwords older the one year.'
  desc 'fix', 'Create application/service account passwords that are at least 15 characters in length and meet complexity requirements. Change application/service account passwords that are manually generated and entered by a system administrator at least annually or whenever an administrator with knowledge of the password leaves the organization.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-11762r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14271'
  tag rid: 'SV-29334r1_rule'
  tag gtitle: 'Application Account Passwords'
  tag fix_id: 'F-13613r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'IAIA-1'
end
