control 'SV-82861' do
  title 'The Mainframe Product  must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. 

Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'If the Mainframe Product employs an external security manager (ESM) for all account management functions, this is not applicable.

Examine user account management configurations. 

If the Mainframe Product account management configuration does not enforce a minimum 15-character password length, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management  to enforce a minimum 15-character password length.'
  impact 0.5
  ref 'DPMS Target SRG-APP-MFPR'
  tag check_id: 'C-68903r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68371'
  tag rid: 'SV-82861r1_rule'
  tag stig_id: 'SRG-APP-000164-MFP-000227'
  tag gtitle: 'SRG-APP-000164-MFP-000227'
  tag fix_id: 'F-74485r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
