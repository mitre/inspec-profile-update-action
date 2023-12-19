control 'SV-217893' do
  title 'The system must require passwords to contain at least one uppercase alphabetic character.'
  desc 'Requiring a minimum number of uppercase characters makes password guessing attacks more difficult by ensuring a larger search space.'
  desc 'check', 'To check how many uppercase characters are required in a password, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

Note: The "ucredit" parameter (as a negative number) will indicate how many uppercase characters are required. The DoD requires at least one uppercase character in a password. This would appear as "ucredit=-1". 

If “ucredit” is not found or not set to the required value, this is a finding.'
  desc 'fix', %q(The pam_cracklib module's "ucredit=" parameter controls requirements for usage of uppercase letters in a password. When set to a negative number, any password will be required to contain that many uppercase characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each uppercase character. 

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "ucredit=-1" after pam_cracklib.so to require use of an uppercase character in passwords.)
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19374r462376_chk'
  tag severity: 'low'
  tag gid: 'V-217893'
  tag rid: 'SV-217893r603264_rule'
  tag stig_id: 'RHEL-06-000057'
  tag gtitle: 'SRG-OS-000069'
  tag fix_id: 'F-19372r462377_fix'
  tag 'documentable'
  tag legacy: ['V-38569', 'SV-50370']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
