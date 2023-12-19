control 'SV-221671' do
  title 'The Oracle Linux operating system must be configured so that when passwords are changed or new passwords are assigned, the new password must contain at least one numeric character.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one of several factors that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that must be tested before the password is compromised.'
  desc 'check', 'Note: The value to require a number of numeric characters to be set is expressed as a negative number in "/etc/security/pwquality.conf".

Check the value for "dcredit" in "/etc/security/pwquality.conf" with the following command:

# grep dcredit /etc/security/pwquality.conf 
dcredit = -1 

If the value of "dcredit" is not set to a negative value, this is a finding.'
  desc 'fix', 'Configure the operating system to enforce password complexity by requiring that at least one numeric character be used by setting the "dcredit" option.

Add the following line to /etc/security/pwquality.conf (or modify the line to have the required value):

dcredit = -1'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23386r419085_chk'
  tag severity: 'medium'
  tag gid: 'V-221671'
  tag rid: 'SV-221671r603260_rule'
  tag stig_id: 'OL07-00-010140'
  tag gtitle: 'SRG-OS-000071-GPOS-00039'
  tag fix_id: 'F-23375r419086_fix'
  tag 'documentable'
  tag legacy: ['V-99083', 'SV-108187']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
