control 'SV-243204' do
  title 'The network device must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Review the configuration and verify SSH Version 1 is not being used for administrative access.

If the device is using an SSHv1 session, this is a finding.'
  desc 'fix', 'Configure the network device to use SSH Version 2.'
  impact 0.5
  ref 'DPMS Target Network WLAN Controller Mgmt'
  tag check_id: 'C-46479r720065_chk'
  tag severity: 'medium'
  tag gid: 'V-243204'
  tag rid: 'SV-243204r720067_rule'
  tag stig_id: 'WLAN-ND-001700'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-46436r720066_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
