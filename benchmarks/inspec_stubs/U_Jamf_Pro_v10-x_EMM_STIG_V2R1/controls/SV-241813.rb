control 'SV-241813' do
  title 'The Jamf Pro EMM must enforce the limit of three consecutive invalid logon attempts by a user.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute forcing, is reduced. Limits are imposed by locking the account.

SFR ID: FMT_SMF.1(2)b. / IA-7-a

'
  desc 'check', 'To verify the Jamf Pro EMM enforces a limit of three consecutive invalid logon attempts by a user, do the following:

1. Log in to the Jamf Pro EMM console.
2. Open "Settings".
3. Select "Jamf Pro User Accounts & Groups".
4. Select "Password Policy" in the upper right corner.
5. Verify that under "Account Lockout" the number of failed attempts before lockout is set to "3" or less.

If the Jamf Pro EMM does not limit the number of consecutive invalid logon attempts by a user to "3" or less, this is a finding.'
  desc 'fix', 'To configure the Jamf Pro EMM server to lock after three consecutive invalid logon attempts by a user, do the following:

1. Open "Settings".
2. Select "Jamf Pro User Accounts & Groups".
3. Select “Password Policy” in the upper right corner.
4. Select "Edit".
5. Under “Account Lockout”, select the drop-down menu to change the number of failed attempts before lockout to "3".
6. Select “Save”.'
  impact 0.5
  ref 'DPMS Target Jamf Pro v10-x EMM'
  tag check_id: 'C-45089r685191_chk'
  tag severity: 'medium'
  tag gid: 'V-241813'
  tag rid: 'SV-241813r879887_rule'
  tag stig_id: 'JAMF-10-100810'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-45048r685192_fix'
  tag satisfies: ['SRG-APP-000065']
  tag 'documentable'
  tag legacy: ['SV-108731', 'V-99627']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
