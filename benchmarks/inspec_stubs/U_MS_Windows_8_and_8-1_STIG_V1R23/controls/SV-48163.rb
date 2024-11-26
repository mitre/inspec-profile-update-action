control 'SV-48163' do
  title 'Local accounts must require passwords.'
  desc 'The lack of password protection enables anyone to gain access to the information system, which opens a backdoor opportunity for intruders to compromise the system as well as other resources.  Local accounts on a system must require passwords.'
  desc 'check', 'Verify all local accounts require passwords.

Run the DUMPSEC utility.
Select "Dump Users as Table" from the "Report" menu.
Select the following fields, and click "Add" for each entry.

UserName
SID
PswdRequired
AcctDisabled
Groups

If any accounts have "No" in the "PswdRequired" column, this is a finding.

Some built-in or application-generated accounts (e.g., Guest, IWAM_, IUSR, etc.) may not have this flag set, even though there are passwords present.  It can be set by entering the following on a command line: "Net user <account_name> /passwordreq:yes".'
  desc 'fix', 'Ensure all local accounts are configured to require passwords to gain access.

The password required flag can be set by entering the following on a command line: "Net user <account_name> /passwordreq:yes".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44863r1_chk'
  tag severity: 'high'
  tag gid: 'V-7002'
  tag rid: 'SV-48163r1_rule'
  tag stig_id: 'WN08-GE-000018'
  tag gtitle: 'Password Requirement'
  tag fix_id: 'F-41301r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
