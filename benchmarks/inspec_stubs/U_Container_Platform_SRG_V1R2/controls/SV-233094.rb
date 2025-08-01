control 'SV-233094' do
  title 'The container platform must require the change of at least 15 of the total number of characters when passwords are changed.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.'
  desc 'check', 'Review the container platform configuration to determine if it requires the change of at least 15 of the total number of characters when passwords are changed. 

If the container platform does not require the change of at least 15 of the total number of characters when passwords are changed, this is a finding.'
  desc 'fix', 'Configure the container platform to require the change of at least 15 of the total number of characters when passwords are changed.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36030r601732_chk'
  tag severity: 'medium'
  tag gid: 'V-233094'
  tag rid: 'SV-233094r601733_rule'
  tag stig_id: 'SRG-APP-000170-CTR-000430'
  tag gtitle: 'SRG-APP-000170'
  tag fix_id: 'F-35998r600770_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
