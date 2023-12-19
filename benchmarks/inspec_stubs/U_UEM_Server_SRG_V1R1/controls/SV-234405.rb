control 'SV-234405' do
  title 'The UEM server must protect the authenticity of communications sessions.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

Application communication sessions are protected utilizing transport encryption protocols, such as TLS. TLS provides web applications with a means to be able to authenticate user sessions and encrypt application traffic. Session authentication can be single (one-way) or mutual (two-way) in nature. Single authentication authenticates the server for the client, whereas mutual authentication provides a means for both the client and the server to authenticate each other. 

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA). 

This requirement addresses communications protection at the application session, versus the network packet, and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of TLS mutual authentication (two-way/bidirectional). 

Satisfies:FIA_ENR_EXT.1.1, FTP_TRP.1.1(2), FTP_TRP.1.1(1)'
  desc 'check', 'Verify the UEM server protects the authenticity of communications sessions.

If the UEM server does not protect the authenticity of communications sessions, this is a finding.'
  desc 'fix', 'Configure the UEM server to protect the authenticity of communications sessions.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37590r614225_chk'
  tag severity: 'medium'
  tag gid: 'V-234405'
  tag rid: 'SV-234405r617355_rule'
  tag stig_id: 'SRG-APP-000219-UEM-000132'
  tag gtitle: 'SRG-APP-000219'
  tag fix_id: 'F-37555r614226_fix'
  tag 'documentable'
  tag cci: ['CCI-001184']
  tag nist: ['SC-23']
end
