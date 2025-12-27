control 'SV-202076' do
  title 'The network device must recognize only system-generated session identifiers.'
  desc 'Network device management web interfaces utilize sessions and session identifiers to control management interface behavior and administrator access. If an attacker can guess the session identifier or can inject or manually insert session information, the session may be compromised.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.'
  desc 'check', 'If the network device uses a web interface for device management, determine if it recognizes only system-generated session identifiers. This requirement may be verified by demonstration, configuration review, or validated test results. If the network device recognizes other session identifiers than the system-generated ones, this is a finding.'
  desc 'fix', 'Configure the network device to recognize only system-generated session identifiers.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2202r381848_chk'
  tag severity: 'medium'
  tag gid: 'V-202076'
  tag rid: 'SV-202076r879638_rule'
  tag stig_id: 'SRG-APP-000223-NDM-000269'
  tag gtitle: 'SRG-APP-000223'
  tag fix_id: 'F-2203r381849_fix'
  tag 'documentable'
  tag legacy: ['SV-69409', 'V-55163']
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
