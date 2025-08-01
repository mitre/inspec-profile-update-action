control 'SV-221669' do
  title 'The Oracle Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one upper-case character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one of several factors that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that must be tested before the password is compromised.'
  desc 'check', 'Note: The value to require a number of upper-case characters to be set is expressed as a negative number in "/etc/security/pwquality.conf".

Check the value for "ucredit" in "/etc/security/pwquality.conf" with the following command:

# grep ucredit /etc/security/pwquality.conf 
ucredit = -1

If the value of "ucredit" is not set to a negative value, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one upper-case character be used by setting the "ucredit" option.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

ucredit = -1'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23384r419079_chk'
  tag severity: 'medium'
  tag gid: 'V-221669'
  tag rid: 'SV-221669r603260_rule'
  tag stig_id: 'OL07-00-010120'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-23373r419080_fix'
  tag 'documentable'
  tag legacy: ['V-99079', 'SV-108183']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
