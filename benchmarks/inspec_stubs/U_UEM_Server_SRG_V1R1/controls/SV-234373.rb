control 'SV-234373' do
  title 'The UEM server must require the change of at least 15 of the total number of characters when passwords are changed.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.'
  desc 'check', 'Verify the UEM server requires the change of at least 15 of the total number of characters when passwords are changed.

If the UEM server does not require the change of at least 15 of the total number of characters when passwords are changed, this is a finding.'
  desc 'fix', 'Configure the UEM server to require the change of at least 15 of the total number of characters when passwords are changed.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37558r614129_chk'
  tag severity: 'medium'
  tag gid: 'V-234373'
  tag rid: 'SV-234373r617355_rule'
  tag stig_id: 'SRG-APP-000170-UEM-000100'
  tag gtitle: 'SRG-APP-000170'
  tag fix_id: 'F-37523r614130_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
