control 'SV-25210' do
  title 'DoD information system access does not require the use of a password.'
  desc 'The lack of password protection enables anyone to gain access to the information system, which opens a backdoor opportunity for intruders to compromise the system as well as other resources within the same administrative domain.'
  desc 'check', 'Using the DUMPSEC utility:

Select “Dump Users as Table” from the “Report” menu.
Select the available fields in the following sequence, and click on the “Add” button for each entry:
UserName
SID
PswdRequired
PswdExpires
LastLogonTime
AcctDisabled
Groups

If any accounts listed in the user report have a “No” in the “PswdRequired” column, then this is a finding.

Note:  Some built-in or application-generated accounts (e.g., Guest, IWAM_, IUSR, etc.) will not have this flag set, even though there are passwords present.  It can be set by entering the following on a command line: “Net user <account_name> /passwordreq:yes”.
 
 
Severity Override: For a DISABLED account(s) with a blank or null password, classify/downgrade this finding to a Category 2 finding.'
  desc 'fix', 'Configure all DoD information systems to require passwords to gain access.

The password required flag can be set by entering the following on a command line: “Net user <account_name> /passwordreq:yes”.'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-4481r1_chk'
  tag severity: 'high'
  tag gid: 'V-7002'
  tag rid: 'SV-25210r1_rule'
  tag gtitle: 'Password Requirement'
  tag fix_id: 'F-6581r1_fix'
  tag 'documentable'
  tag severity_override_guidance: 'For a DISABLED account(s) with a blank or null password, classify/downgrade this finding to a Category 2 finding.'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
