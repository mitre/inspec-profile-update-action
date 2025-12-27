control 'SRG-NET-000147-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must be configured to implement attack-resistant mechanisms for Voice Video Endpoint registration.'
  desc 'Attacks against a Unified Communications Session Manager may include DoS, replay attacks, or cross site scripting. A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack. An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators. 

A cross site scripting vulnerability was demonstrated on a SIP based IP phone by adding scripting code to the "From" field in the SIP invite. Upon receiving the invite, the embedded code was executed by the IP phone embedded web server to download additional malicious code.'
  desc 'check', 'Verify the Unified Communications Session Manager implements attack-resistant mechanisms for Voice Video Endpoint registration.

If the Unified Communications Session Manager does not implement attack-resistant mechanisms for Voice Video Endpoint registration, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to implement attack-resistant mechanisms for Voice Video Endpoint registration.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000147-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000147-VVSM-00101'
  tag rid: 'SRG-NET-000147-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000147-VVSM-00101'
  tag gtitle: 'SRG-NET-000147-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000147-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
