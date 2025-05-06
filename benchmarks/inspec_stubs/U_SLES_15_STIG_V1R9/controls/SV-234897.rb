control 'SV-234897' do
  title 'The SUSE operating system must prevent the use of dictionary words for passwords.'
  desc 'If the SUSE operating system allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Verify the SUSE operating system prevents the use of dictionary words for passwords.

Check that the SUSE operating system prevents the use of dictionary words for passwords with the following command:

> grep pam_cracklib.so /etc/pam.d/common-password
password requisite pam_cracklib.so

If the command does not return anything, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to prevent the use of dictionary words for passwords.

Edit "/etc/pam.d/common-password" and add the following line:

password requisite pam_cracklib.so'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38085r618960_chk'
  tag severity: 'medium'
  tag gid: 'V-234897'
  tag rid: 'SV-234897r622137_rule'
  tag stig_id: 'SLES-15-020290'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-38048r618961_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
