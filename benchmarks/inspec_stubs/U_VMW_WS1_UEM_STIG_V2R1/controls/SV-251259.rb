control 'SV-251259' do
  title 'The Workspace ONE UEM local accounts password must be configured with length of 15 characters.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

SFRID: FMT_SMF.1(2)b. / IA-5 (1) (a)'
  desc 'check', 'Verify WS1 UEM is configured to enforce a local account password length of at least 15 characters for the emergency local account.

1. Log in to the WS1UEM console.
2. Go to Settings >> Admin >> Console Security >> Passwords.
3. Verify "Minimum Password Length" is set to 15.

If the minimum password length is not set to 15, this is a finding.'
  desc 'fix', 'Configure WS1 UEM to enforce a local account password length of at least 15 characters for the emergency local account.

1. Log in to the WS1UEM console.
2. Go to Settings >> Admin >> Console Security >> Passwords.
3. Configure "Minimum Password Length" to 15.'
  impact 0.7
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-54694r805078_chk'
  tag severity: 'high'
  tag gid: 'V-251259'
  tag rid: 'SV-251259r805080_rule'
  tag stig_id: 'VMW1-00-200070'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-54648r805079_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
