control 'SV-239913' do
  title 'The Cisco ASA must be configured to implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Step 1: Verify that FIPS mode is enabled as shown in the example.

fips enable

Step 2: Verify only SSH is configured to only use FIPS-compliant ciphers and that Diffie-Hellman Group 14  is used for the key exchange as shown in the example below.

ssh version 2
ssh cipher encryption fips
ssh key-exchange group dh-group14-sha1

Note: The ASA only supports SSHv2.

If the ASA is not configured to implement replay-resistant authentication mechanisms for network access, this is a finding.'
  desc 'fix', 'Step 1: Enable FIPS mode via the fips enable command.

Step 2: Configure SSH to only use FIPS-compliant ciphers and Diffie-Hellman Group 14 for the key exchange.

ASA(config)# ssh cipher encryption fips 
ASA(config)# ssh key-exchange group dh-group14-sha'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43146r666100_chk'
  tag severity: 'medium'
  tag gid: 'V-239913'
  tag rid: 'SV-239913r666102_rule'
  tag stig_id: 'CASA-ND-000470'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-43105r666101_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
