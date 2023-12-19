control 'SV-218236' do
  title 'The system must require passwords contain no more than three consecutive repeating characters.'
  desc 'To enforce the use of complex passwords, the number of consecutive repeating characters is limited.  Passwords with excessive repeated characters may be more vulnerable to password-guessing attacks.'
  desc 'check', 'Check the maxrepeat setting.

Procedure:
Check the password maxrepeat configuration
# grep pam_cracklib.so /etc/pam.d/system-auth

If the maxrepeat option is missing, this is a finding.
If the maxrepeat option is set to more than 3, this is a finding.'
  desc 'fix', 'Edit "/etc/pam.d/system-auth" to include the line:

password required pam_cracklib.so maxrepeat=3

prior to the "password include system-auth-ac" line.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19711r554045_chk'
  tag severity: 'medium'
  tag gid: 'V-218236'
  tag rid: 'SV-218236r603259_rule'
  tag stig_id: 'GEN000680'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-19709r554046_fix'
  tag 'documentable'
  tag legacy: ['V-11975', 'SV-64079']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
