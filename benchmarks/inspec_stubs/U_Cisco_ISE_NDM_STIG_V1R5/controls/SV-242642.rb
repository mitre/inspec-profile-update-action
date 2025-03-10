control 'SV-242642' do
  title 'For accounts using password authentication, the Cisco ISE must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Navigate to Administration >> System >> Settings >> FIPS Mode.

Verify FIPS Mode is enabled.

If FIPS Mode is enabled, this is not a finding.

If FIPS mode is not configured, but password authentication is configured to use FIPS 140-2/3 validated replay-resistant authentication mechanism for network access to privileged accounts , this can be lowered to a CAT 3 finding.'
  desc 'fix', 'Enable FIPS Mode in Cisco ISE to ensure FIPS 140-2/3 algorithms are used in all security functions requiring cryptographic functions.

1. Choose Administration >> System >> Settings >> FIPS Mode.
2. Choose the "Enabled" option from the FIPS Mode drop-down list.
3. Click "Save" and restart the node.

NOTE: Configuring FIPS mode is the required DoD configuration. However, this requirement can be lowered to a CAT 3 if the alternative manual configuration is used to configure individual protocols.'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45917r864201_chk'
  tag severity: 'medium'
  tag gid: 'V-242642'
  tag rid: 'SV-242642r879597_rule'
  tag stig_id: 'CSCO-NM-000370'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-45874r864202_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
