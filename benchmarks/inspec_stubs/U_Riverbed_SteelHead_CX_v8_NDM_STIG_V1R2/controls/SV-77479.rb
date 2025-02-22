control 'SV-77479' do
  title 'Riverbed Optimization System (RiOS) must generate unique session identifiers using a FIPS 140-2 approved random number generator.'
  desc 'Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

This requirement is applicable to devices that use a web interface for device management. Recommended best practice is that the FIPS license be installed and utilized.'
  desc 'check', 'Verify that RiOS is configured to generate unique session identifiers using a FIPS 140-2 approved random number generator.

Navigate to the device CLI
Type: enable
Type: conf t
Type: show fips status
Verify that "FIPS Mode: Enabled" is displayed on the console

If "FIPS Mode: Enabled" is not displayed on the console, this is a finding.'
  desc 'fix', 'Configure RiOS is configured to generate unique session identifiers using a FIPS 140-2 approved random number generator.

Navigate to the device CLI
Type: enable
Type: conf t
Type: fips enable
Type: write memory
Type: reload

Type: show fips status
Verify that "FIPS Mode: Enabled" is displayed on the screen.

Type: exit
Type: exit'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63741r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62989'
  tag rid: 'SV-77479r1_rule'
  tag stig_id: 'RICX-DM-000141'
  tag gtitle: 'SRG-APP-000224-NDM-000270'
  tag fix_id: 'F-68907r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
