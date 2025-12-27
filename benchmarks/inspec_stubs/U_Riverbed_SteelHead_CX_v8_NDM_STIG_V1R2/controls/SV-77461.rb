control 'SV-77461' do
  title 'Riverbed Optimization System (RiOS) must require that when a password is changed, the characters are changed in at least 15 of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.'
  desc 'check', 'Verify that RiOS is configured to require that when a password is changed, the characters are changed in at least 15 of the positions within the password.

Navigate to the device Management Console
Navigate to Configure >> Security >> Password Policy

Verify that "Minimum Character Difference Between Passwords:" is set to "15"

If "Minimum Character Difference Between Passwords:" is not set to "15", this is a finding.'
  desc 'fix', 'Configure RiOS to require that when a password is changed, the characters are changed in at least 15 of the positions within the password.

Navigate to the device Management Console
Navigate to Configure >> Security >> Password Policy

Set the value of "Minimum Character Difference Between Passwords:" to "15"

Click "Apply"
Navigate to the top of the web page and click "Save" to save these settings permanently'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63723r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62971'
  tag rid: 'SV-77461r1_rule'
  tag stig_id: 'RICX-DM-000119'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-68889r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']
end
