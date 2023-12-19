control 'SV-207392' do
  title 'The VMM must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the VMM. Authentication sessions between the authenticator and the VMM validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A privileged account is any VMM account with authorizations of a privileged user.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Verify the VMM implements replay-resistant authentication mechanisms for network access to privileged accounts.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7649r365586_chk'
  tag severity: 'medium'
  tag gid: 'V-207392'
  tag rid: 'SV-207392r854604_rule'
  tag stig_id: 'SRG-OS-000112-VMM-000560'
  tag gtitle: 'SRG-OS-000112'
  tag fix_id: 'F-7649r365587_fix'
  tag 'documentable'
  tag legacy: ['SV-71245', 'V-56985']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
