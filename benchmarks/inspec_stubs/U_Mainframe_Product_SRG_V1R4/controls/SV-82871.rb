control 'SV-82871' do
  title 'The Mainframe Product must enforce password complexity by requiring that at least one special character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor in determining how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised. 

Special characters are  characters that are not alphanumeric. Examples include: ~ ! @ # $ % ^ *.'
  desc 'check', 'If the Mainframe Product employs an external security manager (ESM) for all account management functions, this is not applicable.

Examine user account management configurations.
 
If the Mainframe Product does not enforce password complexity  by requiring  at least one special character be used, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product to enforce password complexity by requiring the use of at least one special character in passwords.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68911r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68381'
  tag rid: 'SV-82871r1_rule'
  tag stig_id: 'SRG-APP-000169-MFP-000231'
  tag gtitle: 'SRG-APP-000169-MFP-000231'
  tag fix_id: 'F-74495r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
