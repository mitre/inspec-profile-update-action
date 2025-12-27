control 'SV-256080' do
  title 'The Riverbed NetProfiler must be configured to enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

'
  desc 'check', 'Go to Administration >> Account Management >> User Accounts. 

Click the "Settings" button. 

Check under "Password Requirements". 

If "Minimum number of characters" is set not to "15", this is a finding.'
  desc 'fix', 'Go to Administration >> Account Management >> User Accounts. 

Click the "Settings" button. 

Under "Password Requirements", change the "Minimum number of characters" to "15".'
  impact 0.5
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59754r882746_chk'
  tag severity: 'medium'
  tag gid: 'V-256080'
  tag rid: 'SV-256080r882748_rule'
  tag stig_id: 'RINP-DM-000031'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-59697r882747_fix'
  tag satisfies: ['SRG-APP-000164-NDM-000252', 'SRG-APP-000170-NDM-000329']
  tag 'documentable'
  tag cci: ['CCI-000195', 'CCI-000205']
  tag nist: ['IA-5 (1) (b)', 'IA-5 (1) (a)']
end
