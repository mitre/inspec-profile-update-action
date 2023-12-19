control 'SV-234894' do
  title 'The SUSE operating system must not allow passwords to be reused for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', 'Verify the SUSE operating system prohibits the reuse of a password for a minimum of five generations.

Check that the SUSE operating system prohibits the reuse of a password for a minimum of five generations with the following command:

> grep pam_pwhistory.so /etc/pam.d/common-password

password requisite pam_pwhistory.so remember=5 use_authtok

If the command does not return a result, or the returned line is commented out, has a second column value different from "requisite", does not contain "remember" value, the value is less than "5", or is missing the "use_authtok" keyword, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system password history to prohibit the reuse of a password for a minimum of five generations.

Edit "/etc/pam.d/common-password" and edit the line containing "pam_pwhistory.so" to contain the option "remember=5 use_authtok" after the third column.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38082r618951_chk'
  tag severity: 'medium'
  tag gid: 'V-234894'
  tag rid: 'SV-234894r622137_rule'
  tag stig_id: 'SLES-15-020250'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-38045r618952_fix'
  tag 'documentable'
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
