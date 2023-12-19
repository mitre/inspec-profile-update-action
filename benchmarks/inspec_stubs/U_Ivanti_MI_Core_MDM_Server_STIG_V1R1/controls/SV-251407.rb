control 'SV-251407' do
  title 'The Ivanti MobileIron Core server must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

'
  desc 'check', 'Verify a 15-character length for local user accounts has been configured:

1. Log in to the Core console.
2. Security >> Password Policy.
3. Verify the Min Password Length is set to 15.

 If the Min Password Length is not set to 15, this is a finding.'
  desc 'fix', 'Configure a 15-character length for local user accounts:

1. Log in to the Core console.
2. Security >> Password Policy.
3. Set Min Password Length to 15.'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54842r806351_chk'
  tag severity: 'medium'
  tag gid: 'V-251407'
  tag rid: 'SV-251407r806353_rule'
  tag stig_id: 'IMIC-11-004800'
  tag gtitle: 'SRG-APP-000164-UEM-000094'
  tag fix_id: 'F-54795r806352_fix'
  tag satisfies: ['FMT_SMF.1(2)b \nReference: PP-MDM-431018']
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
