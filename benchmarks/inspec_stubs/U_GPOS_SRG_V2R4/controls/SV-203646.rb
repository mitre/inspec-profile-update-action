control 'SV-203646' do
  title 'The operating system must implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the operating system. Authentication sessions between the authenticator and the operating system validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A non-privileged account is any operating system account with authorizations of a non-privileged user.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Verify the operating system implements replay-resistant authentication mechanisms for network access to non-privileged accounts. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3771r557183_chk'
  tag severity: 'medium'
  tag gid: 'V-203646'
  tag rid: 'SV-203646r557185_rule'
  tag stig_id: 'SRG-OS-000113-GPOS-00058'
  tag gtitle: 'SRG-OS-000113'
  tag fix_id: 'F-3771r557184_fix'
  tag 'documentable'
  tag legacy: ['V-56767', 'SV-71027']
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
