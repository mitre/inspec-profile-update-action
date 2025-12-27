control 'SV-250989' do
  title 'MobileIron Sentry device must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Review MobileIron Sentry configuration to verify that a minimum 15-character password is set.

1. Log in to MobileIron Sentry System Manager portal. 
2. Go to the "Security" tab. 
3. Go to Identity Source >> Password Policy. 
4. Verify the "Minimum Password Length" is set to 15 or more.

If the password character length is not set 15 or more, this is a finding.'
  desc 'fix', 'Configure the MobileIron Sentry Local User Password Policy to enforce a minimum 15-character password.

1. Log in to MobileIron Sentry System Manager portal.
2. Go to the "Security" tab. 
3. Go to Password Policy. 
4. Set the "Minimum Password Length" value to 15 or more.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54424r802187_chk'
  tag severity: 'medium'
  tag gid: 'V-250989'
  tag rid: 'SV-250989r802189_rule'
  tag stig_id: 'MOIS-ND-000420'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-54378r802188_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
