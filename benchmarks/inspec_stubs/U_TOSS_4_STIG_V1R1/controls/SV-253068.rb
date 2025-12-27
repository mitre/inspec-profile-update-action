control 'SV-253068' do
  title 'TOSS must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify TOSS prohibits password reuse for a minimum of five generations.

Check for the value of the "remember" argument in "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" with the following command:

$ sudo grep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth

/etc/pam.d/system-auth:password required pam_pwhistory.so use_authtok remember=5 retry=3
/etc/pam.d/password-auth:password required pam_pwhistory.so use_authtok remember=5 retry=3

If either file is missing "pam_pwhistory.so" and does not have the "remember" module argument set, is commented out, or the value of the "remember" module argument is set to less than "5", this is a finding.'
  desc 'fix', 'Configure TOSS to prohibit password reuse for a minimum of five generations.

Add the following line in "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" (or modify the line to have the required value):

password required pam_pwhistory.so use_authtok remember=5 retry=3'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56521r824874_chk'
  tag severity: 'medium'
  tag gid: 'V-253068'
  tag rid: 'SV-253068r824876_rule'
  tag stig_id: 'TOSS-04-040130'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-56471r824875_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
