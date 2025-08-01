control 'SV-70257' do
  title 'Web server session IDs must be sent to the client using SSL/TLS.'
  desc 'The HTTP protocol is a stateless protocol. To maintain a session, a session identifier is used. The session identifier is a piece of data that is used to identify a session and a user. If the session identifier is compromised by an attacker, the session can be hijacked. By encrypting the session identifier, the identifier becomes more difficult for an attacker to hijack, decrypt, and use before the session has expired.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine whether the session identifier is being sent to the client encrypted.

If the web server does not encrypt the session identifier, this is a finding.'
  desc 'fix', 'Configure the web server to encrypt the session identifier for transmission to the client.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-56573r2_chk'
  tag severity: 'medium'
  tag gid: 'V-56003'
  tag rid: 'SV-70257r2_rule'
  tag stig_id: 'SRG-APP-000439-WSR-000152'
  tag gtitle: 'SRG-APP-000439-WSR-000152'
  tag fix_id: 'F-60881r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
