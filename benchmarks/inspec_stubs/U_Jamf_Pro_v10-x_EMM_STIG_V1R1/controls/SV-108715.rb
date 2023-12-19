control 'SV-108715' do
  title 'The Jamf Pro EMM local accounts must be configured with at least one lowercase character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

SFR ID: FMT_SMF.1(2)b. / IA-5 (1) (a)

'
  desc 'check', 'To verify the "Require lowercase character" of the local accounts password is selected, do the following:

1. Open the Jamf Pro EMM console.
2. Click "Settings".
3. Click "System Settings".
4. Click "Jamf Pro System User Accounts & Groups".
5. Click "Password Policy".
6. Verify "Require lowercase character" is selected.

If "Require lowercase character" is not selected, this is a finding.'
  desc 'fix', 'To configure the "Require lowercase character" of the local accounts password, do the following:

1. Open the Jamf Pro EMM console.
2. Click "Settings".
3. Click "System Settings".
4. Click "Jamf Pro System User Accounts & Groups".
5. Click "Password Policy".
6. Click "Edit".
7. Select "Require lowercase character"'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98461r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99611'
  tag rid: 'SV-108715r1_rule'
  tag stig_id: 'JAMF-10-100710'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-105295r1_fix'
  tag satisfies: ['SRG-APP-000167']
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
