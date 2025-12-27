control 'SV-221675' do
  title 'The Oracle Linux operating system must be configured so that when passwords are changed the number of repeating consecutive characters must not be more than three characters.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one of several factors that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'The "maxrepeat" option sets the maximum number of allowed same consecutive characters in a new password.

Check for the value of the "maxrepeat" option in "/etc/security/pwquality.conf" with the following command:

# grep maxrepeat /etc/security/pwquality.conf 
maxrepeat = 3

If the value of "maxrepeat" is set to more than "3", this is a finding.'
  desc 'fix', 'Configure the operating system to require the change of the number of repeating consecutive characters when passwords are changed by setting the "maxrepeat" option.

Add the following line to "/etc/security/pwquality.conf conf" (or modify the line to have the required value):

maxrepeat = 3'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23390r419097_chk'
  tag severity: 'medium'
  tag gid: 'V-221675'
  tag rid: 'SV-221675r603260_rule'
  tag stig_id: 'OL07-00-010180'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-23379r419098_fix'
  tag 'documentable'
  tag legacy: ['V-99091', 'SV-108195']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
