control 'SV-82865' do
  title 'The Mainframe Product must enforce password complexity by requiring that at least one lowercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'If the Mainframe Product employs an external security manager (ESM) for all account management functions, this is not applicable.

Examine user account management configurations. 

If the Mainframe Product account management configurations do not require at least one lowercase character be used in passwords, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to require the use of at least one lowercase character in passwords.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68907r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68375'
  tag rid: 'SV-82865r1_rule'
  tag stig_id: 'SRG-APP-000167-MFP-000229'
  tag gtitle: 'SRG-APP-000167-MFP-000229'
  tag fix_id: 'F-74489r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
