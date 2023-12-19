control 'SV-207375' do
  title 'The VMM must require the change of at least 8 of the total number of characters when passwords are changed.'
  desc 'If the VMM allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.'
  desc 'check', 'Verify the VMM requires the change of at least 8 of the total number of characters when passwords are changed.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to require the change of at least 8 of the total number of characters when passwords are changed.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7632r365535_chk'
  tag severity: 'medium'
  tag gid: 'V-207375'
  tag rid: 'SV-207375r378748_rule'
  tag stig_id: 'SRG-OS-000072-VMM-000390'
  tag gtitle: 'SRG-OS-000072'
  tag fix_id: 'F-7632r365536_fix'
  tag 'documentable'
  tag legacy: ['SV-71231', 'V-56971']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
