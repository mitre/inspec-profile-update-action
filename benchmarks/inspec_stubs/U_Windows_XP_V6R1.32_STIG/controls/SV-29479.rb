control 'SV-29479' do
  title 'User account is dormant.'
  desc 'Outdated or unused accounts, provide penetration points that may go undetected.'
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

If any enabled accounts have not been logged into within the past 35 days, then this is a finding.  This can be ascertained by examining the time in the “LastLogonTime” column.  The following accounts are exempt from this check:

The built-in administrator account
The built-in guest account
Application accounts
The “IUSR”-guest account (used with IIS or Peer Web Services)
Accounts that are less than 35 days old
Disabled accounts

Note: The reviewer should review the list with the SA to determine the finding validity for each account reported.
  
Note: The following command can be used on Windows 2003/2008 Active Directory if DumpSec cannot be run:

Open a Command Prompt
Enter “Dsquery user -limit 0 -inactive 5 -o rdn” (This command will only work if the domain is at least at a Windows Server 2003 functional level, not Windows 2000 Native).
A list of user accounts that have been inactive for 5 weeks will be displayed.

Disabled Accounts can be determined by using the following:
Enter “Dsquery user -limit 0 -disabled -o rdn”.

Documentable Explanation: Dormant accounts that have been reviewed and deemed to be required should be documented with the IAO.'
  desc 'fix', 'Regularly review accounts to determine if they are still active.  Accounts that have not been used in the last 35 days should either be removed or disabled.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-393r1_chk'
  tag severity: 'low'
  tag gid: 'V-1112'
  tag rid: 'SV-29479r1_rule'
  tag gtitle: 'Dormant Accounts'
  tag fix_id: 'F-5758r1_fix'
  tag false_positives: 'The reviewer should review the list with the SA to determine the finding validity for each account reported.'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'IAAC-1'
end
