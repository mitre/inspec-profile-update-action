control 'SV-48033' do
  title 'Outdated or unused accounts must be removed from the system.'
  desc 'Outdated or unused accounts provide penetration points that may go undetected.  Inactive accounts must be deleted if no longer necessary or, if still required, disable until needed.'
  desc 'check', 'Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry:

UserName
SID
LastLogonTime
AcctDisabled

Review the "LastLogonTime".
If any enabled accounts have not been logged on to within the past 35 days, this is a finding.

The following accounts are exempt:
Built-in administrator account (SID ending in 500)
Built-in guest account (SID ending in 501)
Application accounts
Disabled accounts

Review the list to determine the finding validity for each account reported.

If the organization has a need for special purpose local user accounts such as a backup administrator account (see V-14224), this must be documented with the ISSO.  This would not be a finding.

Dormant accounts that have been reviewed and deemed to be required must be documented with the ISSO.'
  desc 'fix', 'Regularly review accounts to determine if they are still active.  Accounts that have not been used in the last 35 days must be removed or disabled.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44771r5_chk'
  tag severity: 'low'
  tag gid: 'V-1112'
  tag rid: 'SV-48033r2_rule'
  tag stig_id: 'WN08-GE-000007'
  tag gtitle: 'Dormant Accounts'
  tag fix_id: 'F-41171r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000795']
  tag nist: ['IA-4 e']
end
