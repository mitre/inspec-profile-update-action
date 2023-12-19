control 'SV-95613' do
  title 'AAA Services must be configured to enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function.

Where passwords (to include randomly assigned passwords, shared secrets, and pre-shared keys) are used, verify AAA Services are configured to enforce a minimum 15-character password length. This requirement may be verified by demonstration or configuration review.

If AAA Services are not configured to enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure AAA Services to enforce a minimum 15-character password length. This includes randomly assigned passwords, shared secrets, and pre-shared keys.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80641r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80903'
  tag rid: 'SV-95613r1_rule'
  tag stig_id: 'SRG-APP-000164-AAA-000450'
  tag gtitle: 'SRG-APP-000164-AAA-000450'
  tag fix_id: 'F-87759r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
