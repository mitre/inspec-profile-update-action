control 'SV-253063' do
  title 'TOSS must require the change of at least eight characters when passwords are changed.'
  desc 'If the operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

If the password length is an odd number then number of changed characters must be rounded up. For example, a password length of 15 characters must require the change of at least 8 characters.

TOSS utilizes "pwquality" as a mechanism to enforce password complexity. The "difok" option sets the number of characters in a password that must not be present in the old password.'
  desc 'check', 'Verify the value of the "difok" option in "/etc/security/pwquality.conf" with the following command:

$ sudo grep difok /etc/security/pwquality.conf 
difok = 8

If the value of "difok" is set to less than "8" or is commented out, this is a finding.'
  desc 'fix', 'Configure the operating system to require the change of at least eight of the total number of characters when passwords are changed by setting the "difok" option.

Add the following line to "/etc/security/pwquality.conf" (or modify the line to have the required value):

difok = 8'
  impact 0.5
  ref 'DPMS Target TOSS 4'
  tag check_id: 'C-56516r824859_chk'
  tag severity: 'medium'
  tag gid: 'V-253063'
  tag rid: 'SV-253063r824861_rule'
  tag stig_id: 'TOSS-04-040080'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-56466r824860_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
