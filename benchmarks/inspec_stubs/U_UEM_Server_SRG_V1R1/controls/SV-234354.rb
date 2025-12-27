control 'SV-234354' do
  title 'The UEM server must be configured to use only documented platform APIs.'
  desc 'Authenticity protection provides protection against man-in-the-middle attacks/session hijacking and the insertion of false information into sessions.

Application communication sessions are protected utilizing transport encryption protocols, such as TLS. TLS provides web applications with a means to authenticate user sessions and encrypt application traffic. Session authentication can be single (one-way) or mutual (two-way) in nature. Single authentication authenticates the server for the client, whereas mutual authentication provides a means for both the client and the server to authenticate each other. 

This requirement applies to applications that utilize communications sessions. This includes, but is not limited to, web-based applications and Service-Oriented Architectures (SOA). 

This requirement addresses communications protection at the application session, versus the network packet, and establishes grounds for confidence at both ends of communications sessions in ongoing identities of other parties and in the validity of information transmitted. Depending on the required degree of confidentiality and integrity, web services/SOA will require the use of TLS mutual authentication (two-way/bidirectional). 

Satisfies:FPT_API_EXT.1.1'
  desc 'check', 'Verify the UEM server uses only documented platform APIs.

If the UEM server does not use only documented platform APIs, this is a finding.'
  desc 'fix', 'Configure the UEM server to be configured to use only documented platform APIs.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37539r614072_chk'
  tag severity: 'medium'
  tag gid: 'V-234354'
  tag rid: 'SV-234354r617397_rule'
  tag stig_id: 'SRG-APP-000142-UEM-000081'
  tag gtitle: 'SRG-APP-000142'
  tag fix_id: 'F-37504r614073_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
