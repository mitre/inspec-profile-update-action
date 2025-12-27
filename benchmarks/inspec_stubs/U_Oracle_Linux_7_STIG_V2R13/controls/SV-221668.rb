control 'SV-221668' do
  title 'The Oracle Linux operating system must be configured so that when passwords are changed or new passwords are established, pwquality must be used.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

Satisfied: SRG-OS-000480-GPOS-00229, SRG-OS-000069-GPOS-00037'
  desc 'check', 'Verify the operating system uses "pwquality" to enforce the password complexity rules. 

Check for the use of "pwquality" with the following command:

     # cat /etc/pam.d/system-auth | grep pam_pwquality

     password requisite pam_pwquality.so retry=3

If the command does not return an uncommented line containing the value "pam_pwquality.so" as shown, this is a finding.

If the value of "retry" is set to "0" or greater than "3", this is a finding.'
  desc 'fix', 'Configure the operating system to use "pwquality" to enforce password complexity rules.

Add the following line to "/etc/pam.d/system-auth" (or modify the line to have the required value):

     password requisite pam_pwquality.so retry=3

Note: The value of "retry" should be between "1" and "3".'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23383r902777_chk'
  tag severity: 'medium'
  tag gid: 'V-221668'
  tag rid: 'SV-221668r902779_rule'
  tag stig_id: 'OL07-00-010119'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-23372r902778_fix'
  tag 'documentable'
  tag legacy: ['V-99077', 'SV-108181']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
