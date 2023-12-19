control 'SV-108723' do
  title 'The Jamf Pro EMM local accounts must be configured with password minimum lifetime of 24 hours.'
  desc "Enforcing a minimum password lifetime helps prevent repeated password changes to defeat the password reuse or history enforcement requirement.

Restricting this setting limits the user's ability to change their password. Passwords need to be changed at specific policy based intervals; however, if the application allows the user to immediately and continually change their password, then the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

SFR ID: FMT_SMF.1(2)b. / IA-5 (1) (d)

"
  desc 'check', 'To verify the "Minimum password Age" of "1" day for the local accounts password is set, do the following:

1. Open the Jamf Pro EMM console.
2. Click "Settings".
3. Click "System Settings".
4. Click "Jamf Pro System User Accounts & Groups".
5. Click "Password Policy".
6. Verify "Minimum Password Age" is set to "1" day.

If the "Minimum Password Age" is not set to "1" day, this is a finding.'
  desc 'fix', 'To configure the "Minimum Password Age" to "1" day for the local accounts password, do the following:

1. Open the Jamf Pro EMM console.
2. Click "Settings".
3. Click "System Settings".
4. Click "Jamf Pro System User Accounts & Groups".
5. Click "Password Policy".
6. Click "Edit".
7. Set the "Minimum Password Age" to "1" day.'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98469r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99619'
  tag rid: 'SV-108723r1_rule'
  tag stig_id: 'JAMF-10-100750'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-105303r1_fix'
  tag satisfies: ['SRG-APP-000173']
  tag 'documentable'
  tag cci: ['CCI-000198']
  tag nist: ['IA-5 (1) (d)']
end
