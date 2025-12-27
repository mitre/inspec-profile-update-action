control 'SV-202077' do
  title 'The network device must generate unique session identifiers using a FIPS 140-2 approved random number generator.'
  desc 'Sequentially generated session IDs can be easily guessed by an attacker. Employing the concept of randomness in the generation of unique session identifiers helps to protect against brute-force attacks to determine future session identifiers.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

This requirement is applicable to devices that use a web interface for device management.'
  desc 'check', 'If the network device uses a web interface for device management, determine if it generates unique session identifiers using a FIPS 140-2 approved random number generator. This requirement may be verified by validated NIST certification and vendor documentation. If the network device does not use unique session identifiers for its web interface for device management, this is a finding.'
  desc 'fix', 'Configure the network device to generate unique session identifiers using a FIPS 140-2 approved random number generator.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2203r381851_chk'
  tag severity: 'medium'
  tag gid: 'V-202077'
  tag rid: 'SV-202077r879639_rule'
  tag stig_id: 'SRG-APP-000224-NDM-000270'
  tag gtitle: 'SRG-APP-000224'
  tag fix_id: 'F-2204r381852_fix'
  tag 'documentable'
  tag legacy: ['SV-69413', 'V-55167']
  tag cci: ['CCI-001188']
  tag nist: ['SC-23 (3)']
end
