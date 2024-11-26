control 'SV-221670' do
  title 'The Oracle Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one lower-case character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one of several factors that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that must be tested before the password is compromised.'
  desc 'check', 'Note: The value to require a number of lower-case characters to be set is expressed as a negative number in "/etc/security/pwquality.conf".

Check the value for "lcredit" in "/etc/security/pwquality.conf" with the following command:

# grep lcredit /etc/security/pwquality.conf 
lcredit = -1 

If the value of "lcredit" is not set to a negative value, this is a finding.'
  desc 'fix', 'Configure the system to require at least one lower-case character when creating or changing a password.

Add or modify the following line 
in "/etc/security/pwquality.conf":

lcredit = -1'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23385r419082_chk'
  tag severity: 'medium'
  tag gid: 'V-221670'
  tag rid: 'SV-221670r603260_rule'
  tag stig_id: 'OL07-00-010130'
  tag gtitle: 'SRG-OS-000070-GPOS-00038'
  tag fix_id: 'F-23374r419083_fix'
  tag 'documentable'
  tag legacy: ['V-99081', 'SV-108185']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
