control 'SV-206828' do
  title 'The Voice Video Session Manager must implement attack-resistant mechanisms for Voice Video endpoint registration.'
  desc 'Attacks against a Voice Video Session Manager may include DoS, replay attacks, or cross site scripting. A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack. An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators. 

A cross site scripting vulnerability was demonstrated on a SIP based IP phone by adding scripting code to the "From" field in the SIP invite. Upon receiving the invite, the embedded code was executed by the IP phone embedded web server to download additional malicious code.'
  desc 'check', 'Verify the Voice Video Session Manager implements attack-resistant mechanisms for Voice Video endpoint registration.

If the Voice Video Session Manager does not implement attack-resistant mechanisms for Voice Video endpoint registration, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to implement attack-resistant mechanisms for Voice Video endpoint registration.'
  impact 0.5
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7083r364673_chk'
  tag severity: 'medium'
  tag gid: 'V-206828'
  tag rid: 'SV-206828r508661_rule'
  tag stig_id: 'SRG-NET-000147-VVSM-00009'
  tag gtitle: 'SRG-NET-000147'
  tag fix_id: 'F-7083r364674_fix'
  tag 'documentable'
  tag legacy: ['SV-76581', 'V-62091']
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
