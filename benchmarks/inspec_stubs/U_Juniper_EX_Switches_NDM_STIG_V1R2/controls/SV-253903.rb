control 'SV-253903' do
  title 'The Juniper EX switch must be configured to implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Determine if the network device implements replay-resistant authentication mechanisms for network access to privileged accounts. This requirement may be verified by demonstration, configuration review, or validated test results. This requirement may be met through use of a properly configured authentication server if the device is configured to use the authentication server. 

Verify SSH version 2 is configured for network (remote) access to privileged accounts.
[edit system services ssh]
protocol-version v2;

If the network device does not implement replay-resistant authentication mechanisms for network access to privileged accounts, this is a finding.'
  desc 'fix', 'Configure the network device to implement replay-resistant authentication mechanisms for network access to privileged accounts.

set system services ssh protocol-version v2'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57355r843740_chk'
  tag severity: 'medium'
  tag gid: 'V-253903'
  tag rid: 'SV-253903r843742_rule'
  tag stig_id: 'JUEX-NM-000260'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-57306r843741_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
