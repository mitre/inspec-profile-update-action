control 'SV-203645' do
  title 'The operating system must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the operating system. Authentication sessions between the authenticator and the operating system validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A privileged account is any information system account with authorizations of a privileged user.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Verify the operating system implements replay-resistant authentication mechanisms for network access to privileged accounts. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3770r557180_chk'
  tag severity: 'medium'
  tag gid: 'V-203645'
  tag rid: 'SV-203645r557182_rule'
  tag stig_id: 'SRG-OS-000112-GPOS-00057'
  tag gtitle: 'SRG-OS-000112'
  tag fix_id: 'F-3770r557181_fix'
  tag 'documentable'
  tag legacy: ['V-56765', 'SV-71025']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
