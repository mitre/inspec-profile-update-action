control 'SV-44877' do
  title 'The system must require passwords contain no more than three consecutive repeating characters.'
  desc 'To enforce the use of complex passwords, the number of consecutive repeating characters is limited.  Passwords with excessive repeated characters may be more vulnerable to password-guessing attacks.'
  desc 'check', 'Check the system password maxrepeat setting.

Procedure:
Check the password maxrepeat option
# grep pam_cracklib.so /etc/pam.d/common-password

Confirm the maxrepeat option is set to 3 or less as in the example below:

password required pam_cracklib.so maxrepeat=3

There may be other options on the line. If no such line is found, or the maxrepeat option is more than 3 this is a finding.  A setting of zero disables this option.

NOTE:  This option was not available in SLES 11 until service pack 2(SP2).'
  desc 'fix', 'Edit /etc/pam.d/common-password and set the maxrepeat option to a value of 3 or less on the pam_cracklib line.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42332r5_chk'
  tag severity: 'medium'
  tag gid: 'V-11975'
  tag rid: 'SV-44877r1_rule'
  tag stig_id: 'GEN000680'
  tag gtitle: 'GEN000680'
  tag fix_id: 'F-38310r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
