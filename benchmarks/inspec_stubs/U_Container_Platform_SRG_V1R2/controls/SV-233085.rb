control 'SV-233085' do
  title 'The container platform must implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A non-privileged account is any operating system account with authorizations of a non-privileged user.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Review the container platform configuration to determine if the container platform is configured to provide replay-resistant authentication mechanisms for network access to non-privileged accounts. 

If the container platform is not configured to provide replay-resistant authentication mechanisms for network access to non-privileged accounts, this is a finding.'
  desc 'fix', 'Configure the container platform to provide replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target Container Platform'
  tag check_id: 'C-36021r601718_chk'
  tag severity: 'medium'
  tag gid: 'V-233085'
  tag rid: 'SV-233085r601719_rule'
  tag stig_id: 'SRG-APP-000157-CTR-000385'
  tag gtitle: 'SRG-APP-000157'
  tag fix_id: 'F-35989r600743_fix'
  tag 'documentable'
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
