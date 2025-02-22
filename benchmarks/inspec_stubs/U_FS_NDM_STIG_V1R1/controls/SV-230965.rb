control 'SV-230965' do
  title 'Forescout must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Determine if the network device enforces a minimum 15-character password length. This requirement may be verified by demonstration or configuration review.

1. Log on to the Forescout Administrator UI.
2. From the menu, select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
3. Verify the "minimum length" is configured for "15".

If Forescout does not enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Log on to the Forescout Administrator UI.

1. From the menu, select Tools >> Options >> CounterACT User Profiles >> Password and Sessions.
2. Configure the "minimum length" for "15".'
  impact 0.5
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33895r603734_chk'
  tag severity: 'medium'
  tag gid: 'V-230965'
  tag rid: 'SV-230965r615886_rule'
  tag stig_id: 'FORE-NM-000390'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-33868r603735_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
