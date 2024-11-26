control 'SV-70955' do
  title 'The operating system must require the change of at least 50% of the total number of characters when passwords are changed.'
  desc 'If the operating system allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

If the password length is an odd number then number of changed characters must be rounded up.  For example, a password length of 15 characters must require the change of at least 8 characters.'
  desc 'check', 'Verify the operating system requires the change of at least eight of the total number of characters when passwords are changed. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to require the change of at least eight of the total number of characters when passwords are changed.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57265r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56695'
  tag rid: 'SV-70955r2_rule'
  tag stig_id: 'SRG-OS-000072-GPOS-00040'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-61591r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
