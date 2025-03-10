control 'SV-206473' do
  title 'The Central Log Server must be configured to require the change of at least 8 of the total number of characters when passwords are changed.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.'
  desc 'check', 'Examine the configuration.

Verify the Central Log Server is configured to enforce password complexity by requiring the change of at least 8 of the total number of characters when passwords are changed.

If the Central Log Server is not configured to require the change of at least 8 of the total number of characters when passwords are changed, this is a finding.'
  desc 'fix', 'Configure the Central Log Server to  require the change of at least 8 of the total number of characters when passwords are changed.'
  impact 0.3
  ref 'DPMS Target Central Log Server'
  tag check_id: 'C-6733r285663_chk'
  tag severity: 'low'
  tag gid: 'V-206473'
  tag rid: 'SV-206473r397519_rule'
  tag stig_id: 'SRG-APP-000170-AU-002530'
  tag gtitle: 'SRG-APP-000170'
  tag fix_id: 'F-6733r285664_fix'
  tag 'documentable'
  tag legacy: ['SV-96067', 'V-81353']
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
