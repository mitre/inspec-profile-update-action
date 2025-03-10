control 'SV-253069' do
  title 'TOSS must enforce a minimum 15-character password length.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify TOSS enforces a minimum 15-character password length. The "minlen" option sets the minimum number of characters in a new password.

Check for the value of the "minlen" option in "/etc/security/pwquality.conf" with the following command:

$ sudo grep minlen /etc/security/pwquality.conf
minlen = 15

If the command does not return a "minlen" value of 15 or greater, this is a finding.'
  desc 'fix', 'Configure TOSS to enforce a minimum 15-character password length.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

minlen = 15'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56522r824877_chk'
  tag severity: 'medium'
  tag gid: 'V-253069'
  tag rid: 'SV-253069r824879_rule'
  tag stig_id: 'TOSS-04-040140'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-56472r824878_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
