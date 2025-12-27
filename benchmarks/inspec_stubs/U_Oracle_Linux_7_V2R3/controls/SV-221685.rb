control 'SV-221685' do
  title 'The Oracle Linux operating system must be configured so that passwords are prohibited from reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to reuse their password consecutively when that password has exceeded its defined lifetime, the end result is a password that is not changed per policy requirements.'
  desc 'check', 'Verify the operating system prohibits password reuse for a minimum of five generations.

Check for the value of the "remember" argument in "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" with the following command:

# grep -i remember /etc/pam.d/system-auth /etc/pam.d/password-auth

password requisite pam_pwhistory.so use_authtok remember=5 retry=3

If the line containing the "pam_pwhistory.so" line does not have the "remember" module argument set, is commented out, or the value of the "remember" module argument is set to less than "5", this is a finding.'
  desc 'fix', 'Configure the operating system to prohibit password reuse for a minimum of five generations.

Add the following line in "/etc/pam.d/system-auth" and "/etc/pam.d/password-auth" (or modify the line to have the required value):

password requisite pam_pwhistory.so use_authtok remember=5 retry=3

Note: Manual changes to the listed files may be overwritten by the "authconfig" program. The "authconfig" program should not be used to update the configurations listed in this requirement.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23400r419127_chk'
  tag severity: 'medium'
  tag gid: 'V-221685'
  tag rid: 'SV-221685r603260_rule'
  tag stig_id: 'OL07-00-010270'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-23389r419128_fix'
  tag 'documentable'
  tag legacy: ['SV-108213', 'V-99109']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
