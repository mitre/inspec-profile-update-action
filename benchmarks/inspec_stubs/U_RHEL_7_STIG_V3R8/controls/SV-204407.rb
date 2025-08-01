control 'SV-204407' do
  title 'The Red Hat Enterprise Linux operating system must be configured so that when passwords are changed or new passwords are established, the new password must contain at least one upper-case character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Note: The value to require a number of upper-case characters to be set is expressed as a negative number in "/etc/security/pwquality.conf".

Check the value for "ucredit" in "/etc/security/pwquality.conf" with the following command:

# grep ucredit /etc/security/pwquality.conf 
ucredit = -1

If the value of "ucredit" is not set to a negative value, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one upper-case character be used by setting the "ucredit" option.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

ucredit = -1'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4531r88413_chk'
  tag severity: 'medium'
  tag gid: 'V-204407'
  tag rid: 'SV-204407r603261_rule'
  tag stig_id: 'RHEL-07-010120'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-4531r88414_fix'
  tag 'documentable'
  tag legacy: ['SV-86527', 'V-71903']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
