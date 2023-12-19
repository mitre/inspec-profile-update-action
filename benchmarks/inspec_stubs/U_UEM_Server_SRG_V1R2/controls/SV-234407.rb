control 'SV-234407' do
  title 'The UEM server must recognize only system-generated session identifiers.'
  desc 'Applications utilize sessions and session identifiers to control application behavior and user access. If an attacker can guess the session identifier, or can inject or manually insert session information, the session may be compromised.

Unique session IDs address man-in-the-middle attacks, including session hijacking or insertion of false information into a session. If the attacker is unable to identify or guess the session information related to pending application traffic, they will have more difficulty in hijacking the session or otherwise manipulating valid sessions.

This requirement focuses on communications protection for the application session rather than for the network packet. This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA).'
  desc 'check', 'Verify the UEM server recognizes only system-generated session identifiers.

If the UEM server does not recognize only system-generated session identifiers, this is a finding.'
  desc 'fix', 'Configure the UEM server to recognize only system-generated session identifiers.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37592r614231_chk'
  tag severity: 'medium'
  tag gid: 'V-234407'
  tag rid: 'SV-234407r879638_rule'
  tag stig_id: 'SRG-APP-000223-UEM-000134'
  tag gtitle: 'SRG-APP-000223'
  tag fix_id: 'F-37557r614232_fix'
  tag 'documentable'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
