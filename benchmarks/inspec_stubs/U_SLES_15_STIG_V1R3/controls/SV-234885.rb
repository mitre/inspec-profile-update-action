control 'SV-234885' do
  title 'The SUSE operating system must require the change of at least eight of the total number of characters when passwords are changed.'
  desc 'If the SUSE operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.'
  desc 'check', 'Verify the SUSE operating system requires at least eight characters be changed between the old and new passwords during a password change.

Check that the operating system requires at least eight characters be changed between the old and new passwords during a password change by running the following command:

> grep pam_cracklib.so /etc/pam.d/common-password
password requisite pam_cracklib.so difok=8

If the command does not return anything, the returned line is commented out, or has a second column value different from "requisite", or does not contain "difok", or the value is less than "8", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to require at least eight characters be changed between the old and new passwords during a password change with the following command:

Edit "/etc/pam.d/common-password" and edit the line containing "pam_cracklib.so" to contain the option "difok=8" after the third column.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38073r618924_chk'
  tag severity: 'medium'
  tag gid: 'V-234885'
  tag rid: 'SV-234885r622137_rule'
  tag stig_id: 'SLES-15-020160'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-38036r618925_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
