control 'SV-108713' do
  title 'The Jamf Pro EMM local accounts password must be configured with length of 15 characters.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

SFR ID: FMT_SMF.1(2)b. / IA-5 (1) (a)

'
  desc 'check', 'To verify the length of the local accounts password, do the following:

1. Open the Jamf Pro EMM console.
2. Click "Settings".
3. Click "System Settings".
4. Click "Jamf Pro System User Accounts & Groups".
5. Click "Password Policy".
6. Verify "Minimum Password Length" is set to "15".

If the "Minimum Password Length" is not set to "15", this is a finding.'
  desc 'fix', 'To configure the length of the local accounts password, do the following:

1. Open the Jamf Pro EMM console.
2. Click "Settings".
3. Click "System Settings".
4. Click "Jamf Pro System User Accounts & Groups".
5. Click "Password Policy".
6. Click "Edit".
7. Set "Minimum Password Length" to "15".'
  impact 0.5
  ref 'DPMS Target JAMF v10.x EMM'
  tag check_id: 'C-98459r1_chk'
  tag severity: 'medium'
  tag gid: 'V-99609'
  tag rid: 'SV-108713r1_rule'
  tag stig_id: 'JAMF-10-100700'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-105293r1_fix'
  tag satisfies: ['SRG-APP-000164']
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
