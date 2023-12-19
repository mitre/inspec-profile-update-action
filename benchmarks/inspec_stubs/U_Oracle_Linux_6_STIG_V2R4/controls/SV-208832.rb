control 'SV-208832' do
  title 'The system must require passwords to contain at least one uppercase alphabetic character.'
  desc 'Requiring a minimum number of uppercase characters makes password guessing attacks more difficult by ensuring a larger search space.'
  desc 'check', 'To check how many uppercase characters are required in a password, run the following command:

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

The "ucredit" parameter (as a negative number) will indicate how many uppercase characters are required. The DoD requires at least one uppercase character in a password. This would appear as "ucredit=-1".

If the “ucredit” parameter is not found or not set to the required value, this is a finding.'
  desc 'fix', %q(The pam_cracklib module's "ucredit=" parameter controls requirements for usage of uppercase letters in a password. When set to a negative number, any password will be required to contain that many uppercase characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each uppercase character.

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "ucredit=-1" after pam_cracklib.so to require use of an uppercase character in passwords.)
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9085r357476_chk'
  tag severity: 'low'
  tag gid: 'V-208832'
  tag rid: 'SV-208832r603263_rule'
  tag stig_id: 'OL6-00-000057'
  tag gtitle: 'SRG-OS-000069'
  tag fix_id: 'F-9085r357477_fix'
  tag 'documentable'
  tag legacy: ['V-50913', 'SV-65119']
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
