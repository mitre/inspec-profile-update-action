control 'SRG-NET-000147-VVEP-00101_rule' do
  title 'The Unified Communications Endpoint must be configured to implement replay-resistant authentication mechanisms for network access.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

A nonprivileged account is any operating system account with authorizations of a nonprivileged user. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators. 

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'Verify the Unified Communications Endpoint implements replay-resistant authentication mechanisms for network access. 

If the Unified Communications Endpoint does not implement replay-resistant authentication mechanisms for network access, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to implement replay-resistant authentication mechanisms for network access.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000147-VVEP-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000147-VVEP-00101'
  tag rid: 'SRG-NET-000147-VVEP-00101_rule'
  tag stig_id: 'SRG-NET-000147-VVEP-00101'
  tag gtitle: 'SRG-NET-000147-VVEP-00101'
  tag fix_id: 'F-SRG-NET-000147-VVEP-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
