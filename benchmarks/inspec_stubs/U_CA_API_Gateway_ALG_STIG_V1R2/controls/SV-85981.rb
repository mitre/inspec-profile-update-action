control 'SV-85981' do
  title 'The CA API Gateway providing user authentication intermediary services must implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A non-privileged account is any account with the authorizations of a non-privileged user. Privileged roles are organization-defined roles assigned to individuals that allow those individuals to perform certain security-relevant functions that ordinary users are not authorized to perform. Security-relevant roles include key management, account management, network and system administration, database administration, and web administration.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS). Additional techniques include time-synchronous or challenge-response one-time authenticators.

The CA API Gateway registered services requiring replay-resistance must include an out-of-the-box "Protect Against Message Replay" Assertion that will assist with preventing the replay of authenticated sessions accessing network resources.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and open each of the Registered Services that requires the replay-resistant authentication mechanisms. 

Verify the "Protect Against Message Replay" Assertion is present after the "Authenticate User or Group" or "Authenticate Against Identity Provider" Assertion. 

If the Assertion is not present, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and open each of the Registered Services that require the replay-resistant authentication mechanisms. 

Add the "Protect Against Message Replay" Assertion after the "Authenticate User or Group" or "Authenticate Against Identity Provider" Assertion.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71757r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71357'
  tag rid: 'SV-85981r1_rule'
  tag stig_id: 'CAGW-GW-000340'
  tag gtitle: 'SRG-NET-000147-ALG-000095'
  tag fix_id: 'F-77667r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
