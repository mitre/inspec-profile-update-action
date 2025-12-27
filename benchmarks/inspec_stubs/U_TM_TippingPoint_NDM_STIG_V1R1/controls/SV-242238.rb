control 'SV-242238' do
  title 'The TippingPoint SMS must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'In the SMS client, ensure the SMS password complexity requirements are met. 

1. Under Security, click Edit and Preferences. 
2. If the security level is set to anything except "3 - High", this is a finding. This setting ensures a 15-character minimum, uppercase, lowercase, numbers, and symbols are used.'
  desc 'fix', 'In the SMS client, ensure the SMS password complexity requirements are met.

1. Under Security, click Edit and Preferences. 
2. Change security level to "3 - High". This setting ensures a 15-character minimum, uppercase, lowercase, numbers, and symbols are used.'
  impact 0.5
  ref 'DPMS Target Trend Micro TippingPoint NDM'
  tag check_id: 'C-45513r710719_chk'
  tag severity: 'medium'
  tag gid: 'V-242238'
  tag rid: 'SV-242238r710721_rule'
  tag stig_id: 'TIPP-NM-000240'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-45471r710720_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
