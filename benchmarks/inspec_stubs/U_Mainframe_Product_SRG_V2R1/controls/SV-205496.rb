control 'SV-205496' do
  title 'The Mainframe Product  must enforce password complexity by requiring that at least one uppercase character be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. 

Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'If the Mainframe Product employs an external security manager (ESM) for all account management functions, this is not applicable.

Examine user account management configurations.
 
If the Mainframe Product does not require at least one uppercase character be used in passwords, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to require the use of at least  one uppercase character in passwords.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5762r299721_chk'
  tag severity: 'medium'
  tag gid: 'V-205496'
  tag rid: 'SV-205496r397507_rule'
  tag stig_id: 'SRG-APP-000166-MFP-000228'
  tag gtitle: 'SRG-APP-000166'
  tag fix_id: 'F-5762r299722_fix'
  tag 'documentable'
  tag legacy: ['SV-82863', 'V-68373']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
