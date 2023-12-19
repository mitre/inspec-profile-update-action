control 'SV-234882' do
  title 'The SUSE operating system must enforce passwords that contain at least one uppercase character.'
  desc 'Use of a complex password helps increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.'
  desc 'check', 'Verify the SUSE operating system enforces password complexity by requiring at least one uppercase character.

Check that the operating system enforces password complexity by requiring that at least one uppercase character be used by using the following command:

> grep pam_cracklib.so /etc/pam.d/common-password
password requisite pam_cracklib.so ucredit=-1

If the command does not return anything, the returned line is commented out, or has a second column value different from "requisite", or does not contain "ucredit=-1", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to enforce password complexity by requiring at least one uppercase character.

Edit "/etc/pam.d/common-password" and edit the line containing "pam_cracklib.so" to contain the option "ucredit=-1" after the third column.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38070r618915_chk'
  tag severity: 'medium'
  tag gid: 'V-234882'
  tag rid: 'SV-234882r622137_rule'
  tag stig_id: 'SLES-15-020130'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-38033r618916_fix'
  tag 'documentable'
  tag cci: ['CCI-000192']
  tag nist: ['IA-5 (1) (a)']
end
