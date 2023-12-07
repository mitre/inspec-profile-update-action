control 'SV-95623' do
  title 'AAA Services must be configured to require the change of at least eight of the total number of characters when passwords are changed.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Use of a complex password helps to increase the time and resources required to compromise the password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'If AAA Services rely on directory services for user account management, this is not applicable and the connected directory services must perform this function.

Where passwords are used, verify AAA Services are configured to require the change of at least eight of the total number of characters when passwords are changed. This requirement may be verified by demonstration or configuration review.

If AAA Services are not configured to require the change of at least eight of the total number of characters when passwords are changed, this is a finding.'
  desc 'fix', 'Configure AAA Services to require the change of at least eight of the total number of characters when passwords are changed. 

Note: The best practice would be to require that all characters must be changed with each password change, especially for privileged accounts.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80651r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80913'
  tag rid: 'SV-95623r1_rule'
  tag stig_id: 'SRG-APP-000170-AAA-000500'
  tag gtitle: 'SRG-APP-000170-AAA-000500'
  tag fix_id: 'F-87769r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
