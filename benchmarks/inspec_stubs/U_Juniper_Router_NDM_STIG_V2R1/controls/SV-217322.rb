control 'SV-217322' do
  title 'The Juniper router must be configured to implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Review the router configuration to verify that SSH is configured to use FIPS-140-2 compliant HMACs as shown in the example below.

system {
   …
   …
   …
    services {
        ssh {
            protocol-version v2;
            macs [hmac-sha2-256 hmac-sha2-512];
        }

Note: An SSH configuration enables a server and client to authorize the negotiation of only those algorithms that are configured from the allowed list. If a remote party tries to negotiate using an algorithm that is not part of the allowed list, the request is rejected and the session is not established. 

If the router is not configured to implement replay-resistant authentication mechanisms for network access to privileged accounts, this is a finding.'
  desc 'fix', 'Configure SSH to use FIPS-140-2 compliant HMACs as shown in the example below.

[edit system services]
set ssh protocol-version v2
set ssh macs [hmac-sha2-256 hmac-sha2-512]

Note: An SSH configuration enables a server and client to authorize the negotiation of only those algorithms that are configured from the allowed list. If a user tries to negotiate using an algorithm that is not part of the allowed list, the request is rejected and the session is not established.'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18549r296544_chk'
  tag severity: 'medium'
  tag gid: 'V-217322'
  tag rid: 'SV-217322r397459_rule'
  tag stig_id: 'JUNI-ND-000530'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-18547r296545_fix'
  tag 'documentable'
  tag legacy: ['SV-101229', 'V-91129']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
