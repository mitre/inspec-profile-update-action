control 'SV-68769' do
  title 'The ALG providing user authentication intermediary services must implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A non-privileged account is any account with the authorizations of a non-privileged user. Privileged roles are organization-defined roles assigned to individuals that allow those individuals to perform certain security-relevant functions that ordinary users are not authorized to perform. Security relevant roles include key management, account management, network and system administration, database administration, and web administration.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one time use) or challenges (e.g., TLS). Additional techniques include time-synchronous or challenge-response one-time authenticators.

This requirement applies to ALGs that provide user authentication intermediary services.'
  desc 'check', 'If the ALG does not provide user authentication intermediary services, this is not applicable.

Verify the ALG is configured to implement replay-resistant authentication mechanisms for network access to non-privileged accounts.

If the ALG does not implement replay-resistant authentication mechanisms for network access to non-privileged accounts, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure the ALG to implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55139r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54523'
  tag rid: 'SV-68769r2_rule'
  tag stig_id: 'SRG-NET-000147-ALG-000095'
  tag gtitle: 'SRG-NET-000147-ALG-000095'
  tag fix_id: 'F-59377r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
