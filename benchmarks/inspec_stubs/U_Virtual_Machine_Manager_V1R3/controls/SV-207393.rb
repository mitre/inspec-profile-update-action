control 'SV-207393' do
  title 'The VMM must implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the VMM. Authentication sessions between the authenticator and the VMM validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A non-privileged account is any VMM account with authorizations of a non-privileged user.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Verify the VMM implements replay-resistant authentication mechanisms for network access to non-privileged accounts.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7650r365589_chk'
  tag severity: 'medium'
  tag gid: 'V-207393'
  tag rid: 'SV-207393r854605_rule'
  tag stig_id: 'SRG-OS-000113-VMM-000570'
  tag gtitle: 'SRG-OS-000113'
  tag fix_id: 'F-7650r365590_fix'
  tag 'documentable'
  tag legacy: ['SV-71247', 'V-56987']
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
