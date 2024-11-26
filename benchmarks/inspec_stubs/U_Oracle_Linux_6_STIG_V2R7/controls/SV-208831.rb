control 'SV-208831' do
  title 'The system must require passwords to contain at least one numeric character.'
  desc 'Requiring digits makes password guessing attacks more difficult by ensuring a larger search space.'
  desc 'check', 'To check how many digits are required in a password, run the following command:

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

The "dcredit" parameter (as a negative number) will indicate how many digits are required. The DoD requires at least one digit in a password. This would appear as "dcredit=-1".

If the “dcredit” parameter is not found or not set to the required value, this is a finding.'
  desc 'fix', %q(The pam_cracklib module's "dcredit" parameter controls requirements for usage of digits in a password. When set to a negative number, any password will be required to contain that many digits. When set to a positive number, pam_cracklib will grant +1 additional length credit for each digit.

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "dcredit=-1" after pam_cracklib.so to require use of a digit in passwords.)
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9084r357473_chk'
  tag severity: 'low'
  tag gid: 'V-208831'
  tag rid: 'SV-208831r793616_rule'
  tag stig_id: 'OL6-00-000056'
  tag gtitle: 'SRG-OS-000071'
  tag fix_id: 'F-9084r357474_fix'
  tag 'documentable'
  tag legacy: ['V-50911', 'SV-65117']
  tag cci: ['CCI-000194']
  tag nist: ['IA-5 (1) (a)']
end
