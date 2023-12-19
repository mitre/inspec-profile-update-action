control 'SV-251260' do
  title 'The Workspace ONE UEM local accounts must be configured with at least one lowercase character, one uppercase character, one number, and one special character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

SFR ID: FMT_SMF.1(2)b. / IA-5 (1) (a)'
  desc 'check', 'Verify WS1 UEM is configured to enforce a local account password with at least one lower case letter, one uppercase character, one number, and one special character for the emergency local account.

1. Log in to the WS1UEM console.
2. Go to Settings >> Admin >> Console Security >> Passwords.
3. Verify "Password complexity level" to "Mixed case, alphabetic, numeric and special characters".

If password complexity is not set as listed above, this is a finding.'
  desc 'fix', 'Configure WS1 UEM to enforce a local account password with at least one lower case letter, one uppercase character, one number, and one special character for the emergency local account.

1. Log in to the WS1UEM console.
2. Go to Settings >> Admin >> Console Security >> Passwords.
3. Configure "Password complexity level" to "Mixed case, alphabetic, numeric and special characters".'
  impact 0.7
  ref 'DPMS Target VMware Workspace ONE UEM'
  tag check_id: 'C-54695r806441_chk'
  tag severity: 'high'
  tag gid: 'V-251260'
  tag rid: 'SV-251260r805083_rule'
  tag stig_id: 'VMW1-00-200080'
  tag gtitle: 'PP-MDM-991000'
  tag fix_id: 'F-54649r805082_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
