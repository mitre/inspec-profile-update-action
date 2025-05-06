control 'SV-208834' do
  title 'The system must require passwords to contain at least one lower-case alphabetic character.'
  desc 'Requiring a minimum number of lowercase characters makes password guessing attacks more difficult by ensuring a larger search space.'
  desc 'check', 'To check how many lower-case characters are required in a password, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

The "lcredit" parameter (as a negative number) will indicate how many lower-case characters are required. The DoD requires at least one lower-case character in a password. This would appear as "lcredit=-1".

If the “lcredit” parameter is not found or not set to the required value, this is a finding.'
  desc 'fix', %q(The pam_cracklib module's "lcredit=" parameter controls requirements for usage of lower-case letters in a password. When set to a negative number, any password will be required to contain that many lower-case characters.

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "lcredit=-1" after pam_cracklib.so to require use of a lower-case character in passwords.)
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9087r357482_chk'
  tag severity: 'low'
  tag gid: 'V-208834'
  tag rid: 'SV-208834r793619_rule'
  tag stig_id: 'OL6-00-000059'
  tag gtitle: 'SRG-OS-000070'
  tag fix_id: 'F-9087r357483_fix'
  tag 'documentable'
  tag legacy: ['SV-65123', 'V-50917']
  tag cci: ['CCI-000193']
  tag nist: ['IA-5 (1) (a)']
end
