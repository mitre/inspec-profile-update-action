control 'SV-252190' do
  title 'The HPE Nimble must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Type "userpolicy --info" and review output for line: "Minimum Length". If it is 15 or more, this is not a finding.'
  desc 'fix', 'Set minimum password length to 15 by typing "userpolicy --edit --min_length 15".'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55646r814048_chk'
  tag severity: 'medium'
  tag gid: 'V-252190'
  tag rid: 'SV-252190r814050_rule'
  tag stig_id: 'HPEN-NM-000050'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-55596r814049_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
