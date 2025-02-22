control 'SV-216531' do
  title 'The Cisco router must be configured to implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Review the router configuration to verify that SSH version 2 is configured as shown in the example below.

ssh server v2

Note: IOS XR supports SSHv1 and SSHv2. SSHv1 uses Rivest, Shamir, and Adelman (RSA) keys while SSHv2 uses Digital Signature Algorithm (DSA) keys.

If the router is not configured to implement replay-resistant authentication mechanisms for network access to privileged accounts, this is a finding.'
  desc 'fix', 'Configure the router to use SSH version 2 as shown in the example below.

RP/0/0/CPU0:R3(config)#ssh server v2'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17766r288279_chk'
  tag severity: 'medium'
  tag gid: 'V-216531'
  tag rid: 'SV-216531r879597_rule'
  tag stig_id: 'CISC-ND-000530'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-17763r288280_fix'
  tag 'documentable'
  tag legacy: ['SV-105551', 'V-96413']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
