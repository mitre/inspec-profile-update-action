control 'SV-241806' do
  title 'The Jamf Pro EMM local accounts must be configured with at least one uppercase character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.

SFR ID: FMT_SMF.1(2)b. / IA-5 (1) (a)

'
  desc 'check', 'To verify the "Require uppercase character" of the local accounts password is selected, do the following:

1. Open the Jamf Pro EMM console.
2. Click "Settings".
3. Click "System Settings".
4. Click "Jamf Pro System User Accounts & Groups".
5. Click "Password Policy".
6. Verify "Require uppercase character" is selected.

If "Require uppercase character" is not selected, this is a finding.'
  desc 'fix', 'To configure the "Require uppercase character" of the local accounts password, do the following:

1. Open the Jamf Pro EMM console.
2. Click "Settings".
3. Click "System Settings".
4. Click "Jamf Pro System User Accounts & Groups".
5. Click "Password Policy".
6. Click "Edit".
7. Select "Require uppercase character".'
  impact 0.5
  ref 'DPMS Target Jamf Pro v10-x EMM'
  tag check_id: 'C-45082r685170_chk'
  tag severity: 'medium'
  tag gid: 'V-241806'
  tag rid: 'SV-241806r879887_rule'
  tag stig_id: 'JAMF-10-100720'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-45041r685171_fix'
  tag satisfies: ['SRG-APP-000166']
  tag 'documentable'
  tag legacy: ['SV-108717', 'V-99613']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
