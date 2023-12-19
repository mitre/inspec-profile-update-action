control 'SV-208833' do
  title 'The system must require passwords to contain at least one special character.'
  desc 'Requiring a minimum number of special characters makes password guessing attacks more difficult by ensuring a larger search space.'
  desc 'check', 'To check how many special characters are required in a password, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

The "ocredit" parameter (as a negative number) will indicate how many special characters are required. The DoD requires at least one special character in a password. This would appear as "ocredit=-1".

If the “ocredit” parameter is not found or not set to the required value, this is a finding.'
  desc 'fix', %q(The pam_cracklib module's "ocredit=" parameter controls requirements for usage of special (or ``other'') characters in a password. When set to a negative number, any password will be required to contain that many special characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each special character.

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "ocredit=-1" after pam_cracklib.so to require use of a special character in passwords.)
  impact 0.3
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9086r357479_chk'
  tag severity: 'low'
  tag gid: 'V-208833'
  tag rid: 'SV-208833r603263_rule'
  tag stig_id: 'OL6-00-000058'
  tag gtitle: 'SRG-OS-000266'
  tag fix_id: 'F-9086r357480_fix'
  tag 'documentable'
  tag legacy: ['SV-65121', 'V-50915']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
