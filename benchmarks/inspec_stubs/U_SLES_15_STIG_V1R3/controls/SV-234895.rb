control 'SV-234895' do
  title 'The SUSE operating system must employ passwords with a minimum of 15 characters.'
  desc 'The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised.

Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps determine strength and how long it takes to crack a password. Use of more characters in a password helps exponentially increase the time and/or resources required to compromise the password.'
  desc 'check', 'Verify the SUSE operating system enforces a minimum 15-character password length.

Check that the operating system enforces a minimum 15-character password length with the following command:

> grep pam_cracklib.so /etc/pam.d/common-password
password requisite pam_cracklib.so minlen=15

If the command does not return anything, the returned line is commented out, or has a second column value different from "requisite", or does not contain "minlen" value, or the value is less than "15", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to enforce a minimum 15-character password length.

Edit "/etc/pam.d/common-password" and edit the line containing "pam_cracklib.so" to contain the option "minlen=15" after the third column.

The DoD standard requires a minimum 15-character password length.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38083r618954_chk'
  tag severity: 'medium'
  tag gid: 'V-234895'
  tag rid: 'SV-234895r622137_rule'
  tag stig_id: 'SLES-15-020260'
  tag gtitle: 'SRG-OS-000078-GPOS-00046'
  tag fix_id: 'F-38046r618955_fix'
  tag 'documentable'
  tag cci: ['CCI-000205']
  tag nist: ['IA-5 (1) (a)']
end
