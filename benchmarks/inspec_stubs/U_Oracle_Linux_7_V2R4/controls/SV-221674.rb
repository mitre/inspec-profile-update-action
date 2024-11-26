control 'SV-221674' do
  title 'The Oracle Linux operating system must be configured so that when passwords are changed a minimum of four character classes must be changed.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'The "minclass" option sets the minimum number of required classes of characters for the new password (digits, uppercase, lower-case, others).

Check for the value of the "minclass" option in "/etc/security/pwquality.conf" with the following command:

# grep minclass /etc/security/pwquality.conf 
minclass = 4

If the value of "minclass" is set to less than "4", this is a finding.'
  desc 'fix', 'Configure the operating system to require the change of at least four character classes when passwords are changed by setting the "minclass" option.

Add the following line to "/etc/security/pwquality.conf conf" (or modify the line to have the required value):

minclass = 4'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23389r419094_chk'
  tag severity: 'medium'
  tag gid: 'V-221674'
  tag rid: 'SV-221674r603260_rule'
  tag stig_id: 'OL07-00-010170'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-23378r419095_fix'
  tag 'documentable'
  tag legacy: ['SV-108193', 'V-99089']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
