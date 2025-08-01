control 'SV-242642' do
  title 'For accounts using password authentication, the Cisco ISE must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Navigate to Administration >> System >> Settings >> FIPS Mode.

Verify FIPS Mode is enabled.

If the Cisco ISE does not generate unique session identifiers using a FIPS 140-2 approved RNG, this is a finding.'
  desc 'fix', 'Enable FIPS Mode in Cisco ISE to ensure DRBG is used for all RNG functions.

1. Choose Administration >> System >> Settings >> FIPS Mode.
2. Choose the "Enabled" option from the FIPS Mode drop-down list.
3. Click "Save" and restart the node.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45917r714234_chk'
  tag severity: 'medium'
  tag gid: 'V-242642'
  tag rid: 'SV-242642r714236_rule'
  tag stig_id: 'CSCO-NM-000370'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-45874r714235_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
