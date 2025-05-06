control 'SV-225656' do
  title 'The Samsung SDS EMM must enforce the limit of three consecutive invalid logon attempts by a user.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.

SFR ID: FMT_SMF.1(2)b. / IA-7-a

'
  desc 'check', 'Review the Samsung SDS EMM configuration settings and verify the server is configured to enforce the limit of three consecutive invalid logon attempts by admin.

On the MDM console, verify that the MDM console "Maximum Failed Login Attempts" is set to "3".  

If the administrator incorrectly enters the login password three times, the account is locked.

If the MDM console Maximum Failed Login Attempts is not set to "3", this is a finding.'
  desc 'fix', 'Configure the Samsung SDS EMM to enforce the limit of three consecutive invalid logon attempts by an admin.

On the MDM console, do the following:
1. Log in to the Admin Console using a web browser.
2. Go to Setting >> Server >> Configuration and set "Maximum Failed Login Attempts" to "3".'
  impact 0.5
  ref 'DPMS Target Samsung SDS EMM'
  tag check_id: 'C-27357r560990_chk'
  tag severity: 'medium'
  tag gid: 'V-225656'
  tag rid: 'SV-225656r588007_rule'
  tag stig_id: 'SSDS-00-200250'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-27345r560991_fix'
  tag satisfies: ['SRG-APP-000065', 'PP-MDM-991000']
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
