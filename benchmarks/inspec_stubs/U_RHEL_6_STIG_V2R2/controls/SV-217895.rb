control 'SV-217895' do
  title 'The system must require passwords to contain at least one lower-case alphabetic character.'
  desc 'Requiring a minimum number of lower-case characters makes password guessing attacks more difficult by ensuring a larger search space.'
  desc 'check', 'To check how many lower-case characters are required in a password, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

Note: The "lcredit" parameter (as a negative number) will indicate how many lower-case characters are required. The DoD requires at least one lower-case character in a password. This would appear as "lcredit=-1". 

If “lcredit” is not found or not set to the required value, this is a finding.'
  desc 'fix', %q(The pam_cracklib module's "lcredit=" parameter controls requirements for usage of lower-case letters in a password. When set to a negative number, any password will be required to contain that many lower-case characters. 

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "lcredit=-1" after pam_cracklib.so to require use of a lower-case character in passwords.)
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19376r462382_chk'
  tag severity: 'low'
  tag gid: 'V-217895'
  tag rid: 'SV-217895r603264_rule'
  tag stig_id: 'RHEL-06-000059'
  tag gtitle: 'SRG-OS-000070'
  tag fix_id: 'F-19374r462383_fix'
  tag 'documentable'
  tag legacy: ['V-38571', 'SV-50372']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
