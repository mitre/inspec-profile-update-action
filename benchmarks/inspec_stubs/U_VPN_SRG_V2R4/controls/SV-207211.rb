control 'SV-207211' do
  title 'The TLS VPN must be configured to use replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A non-privileged account is any operating system account with authorizations of a non-privileged user.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user (e.g., VPN, proxy capability). This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'Verify the TLS VPN Gateway is configured to use replay-resistant authentication mechanisms for network access to non-privileged accounts.

If the TLS VPN is not configured to use replay-resistant authentication mechanisms for network access to non-privileged accounts, this is a finding.'
  desc 'fix', 'Configure the TLS VPN Gateway to use replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7471r378254_chk'
  tag severity: 'medium'
  tag gid: 'V-207211'
  tag rid: 'SV-207211r608988_rule'
  tag stig_id: 'SRG-NET-000147-VPN-000520'
  tag gtitle: 'SRG-NET-000147'
  tag fix_id: 'F-7471r378255_fix'
  tag 'documentable'
  tag legacy: ['V-97093', 'SV-106231']
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
