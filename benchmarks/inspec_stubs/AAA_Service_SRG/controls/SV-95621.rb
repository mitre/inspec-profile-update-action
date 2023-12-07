control 'SV-95621' do
  title 'AAA Services must be configured to enforce password complexity by requiring that at least one special character be used.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Use of a complex password helps to increase the time and resources required to compromise the password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised. Special characters are those characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function.

Where passwords (to include randomly assigned passwords, shared secrets, and pre-shared keys) are used, verify AAA Services are configured to enforce password complexity by requiring that at least one special character be used. This requirement may be verified by demonstration or configuration review.

If AAA Services are not configured to require that at least one special character be used, this is a finding.'
  desc 'fix', 'Configure AAA Services to enforce password complexity by requiring that at least one special character be used. This includes randomly assigned passwords, shared secrets, and pre-shared keys.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80649r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80911'
  tag rid: 'SV-95621r1_rule'
  tag stig_id: 'SRG-APP-000169-AAA-000490'
  tag gtitle: 'SRG-APP-000169-AAA-000490'
  tag fix_id: 'F-87767r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
