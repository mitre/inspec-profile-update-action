control 'SV-217121' do
  title 'The SUSE operating system must require the change of at least eight (8) of the total number of characters when passwords are changed.'
  desc 'If the SUSE operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.'
  desc 'check', 'Verify the SUSE operating system requires at least eight (8) characters be changed between the old and new passwords during a password change.

Check that the operating system requires at least eight (8) characters be changed between the old and new passwords during a password change by running the following command:

# grep pam_cracklib.so /etc/pam.d/common-password
password requisite pam_cracklib.so difok=8

If the command does not return anything, the returned line is commented out, or has a second column value different from "requisite", or does not contain "difok", or the value is less than "8", this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to require at least eight characters be changed between the old and new passwords during a password change with the following command:

Edit "/etc/pam.d/common-password" and edit the line containing "pam_cracklib.so" to contain the option "difok=8" after the third column.'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18349r369519_chk'
  tag severity: 'medium'
  tag gid: 'V-217121'
  tag rid: 'SV-217121r603262_rule'
  tag stig_id: 'SLES-12-010190'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-18347r369520_fix'
  tag 'documentable'
  tag legacy: ['SV-91783', 'V-77087']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
