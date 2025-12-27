control 'SV-246852' do
  title 'The network device must enforce a minimum 15-character password length.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.

'
  desc 'check', 'Check for the value of the "minlen" option in "/etc/security/pwquality.conf" with the following command.
grep minlen /etc/security/pwquality.conf 

If the minlen value is not set to "15", this is a finding.'
  desc 'fix', 'Configure the operating system to enforce a minimum class setting.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value).
minlen = 15'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50284r768218_chk'
  tag severity: 'medium'
  tag gid: 'V-246852'
  tag rid: 'SV-246852r768220_rule'
  tag stig_id: 'HYCU-IA-000004'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag fix_id: 'F-50238r768219_fix'
  tag satisfies: ['SRG-APP-000164-NDM-000252', 'SRG-APP-000343-NDM-000289']
  tag 'documentable'
  tag cci: ['CCI-000205', 'CCI-002234']
  tag nist: ['IA-5 (1) (a)', 'AC-6 (9)']
end
