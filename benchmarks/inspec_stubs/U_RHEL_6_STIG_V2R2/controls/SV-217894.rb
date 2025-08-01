control 'SV-217894' do
  title 'The system must require passwords to contain at least one special character.'
  desc 'Requiring a minimum number of special characters makes password guessing attacks more difficult by ensuring a larger search space.'
  desc 'check', 'To check how many special characters are required in a password, run the following command: 

$ grep pam_cracklib /etc/pam.d/system-auth /etc/pam.d/password-auth

Note: The "ocredit" parameter (as a negative number) will indicate how many special characters are required. The DoD requires at least one special character in a password. This would appear as "ocredit=-1". 

If “ocredit” is not found or not set to the required value, this is a finding.'
  desc 'fix', %q(The pam_cracklib module's "ocredit=" parameter controls requirements for usage of special (or "other") characters in a password. When set to a negative number, any password will be required to contain that many special characters. When set to a positive number, pam_cracklib will grant +1 additional length credit for each special character. 

Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth adding "ocredit=-1" after pam_cracklib.so to require use of a special character in passwords.)
  impact 0.3
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19375r462379_chk'
  tag severity: 'low'
  tag gid: 'V-217894'
  tag rid: 'SV-217894r603264_rule'
  tag stig_id: 'RHEL-06-000058'
  tag gtitle: 'SRG-OS-000266'
  tag fix_id: 'F-19373r462380_fix'
  tag 'documentable'
  tag legacy: ['V-38570', 'SV-50371']
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
