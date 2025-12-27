control 'SV-217134' do
  title 'The SUSE operating system must prevent the use of dictionary words for passwords.'
  desc 'If the SUSE operating system allows the user to select passwords based on dictionary words, this increases the chances of password compromise by increasing the opportunity for successful guesses and brute-force attacks.'
  desc 'check', 'Verify the SUSE operating system prevents the use of dictionary words for passwords.

Check that the SUSE operating system prevents the use of dictionary words for passwords with the following command:

# grep pam_cracklib.so /etc/pam.d/common-password
password requisite pam_cracklib.so retry=3

If the command does not return anything, or the returned line is commented out, this is a finding.

If the value of "retry" is greater than 3, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to prevent the use of dictionary words for passwords.

Edit "/etc/pam.d/common-password" and add the following line:

password requisite pam_cracklib.so retry=3'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18362r369558_chk'
  tag severity: 'medium'
  tag gid: 'V-217134'
  tag rid: 'SV-217134r603262_rule'
  tag stig_id: 'SLES-12-010320'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag fix_id: 'F-18360r369559_fix'
  tag 'documentable'
  tag legacy: ['SV-91819', 'V-77123']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
