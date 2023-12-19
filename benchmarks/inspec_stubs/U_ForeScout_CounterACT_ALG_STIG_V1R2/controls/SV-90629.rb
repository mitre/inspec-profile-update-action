control 'SV-90629' do
  title 'CounterACT, when providing user authentication intermediary services, must implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

A non-privileged account is any account with the authorizations of a non-privileged user. Privileged roles are organization-defined roles assigned to individuals that allow those individuals to perform certain security-relevant functions that ordinary users are not authorized to perform. Security relevant roles include key management, account management, network and system administration, database administration, and web administration.

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one time use) or challenges (e.g., TLS). Additional techniques include time-synchronous or challenge-response one-time authenticators.

This requirement applies to ALGs that provide user authentication intermediary services.'
  desc 'check', 'If CounterACT does not provide user authentication intermediary services, this is not applicable.

Verify CounterACT is configured to implement replay-resistant authentication mechanisms for network access to non-privileged accounts. 

1. Connect to CounterACT’s Admin Console and log in.
2. Go to Tools >> Options >> User Directory.
3. Verify the User Directory is configured for secure methods of communication. On the Settings TAB ensure the "Use TLS" radio button is selected. 

If CounterACT does not implement replay-resistant authentication mechanisms for network access to non-privileged accounts, this is a finding.'
  desc 'fix', 'If user authentication intermediary services are provided, configure CounterACT to implement replay-resistant authentication mechanisms for network access to non-privileged accounts. 

1. Connect to CounterACT’s Admin Console and log in.
2. Go to Tools >> Options >> User Directory.
3. Ensure the User Directory is configured for secure methods of communication. On the Settings TAB ensure the "Use TLS" radio button is selected.
4. Select "OK". (Select "Apply" if changes were made.)'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT ALG'
  tag check_id: 'C-75623r1_chk'
  tag severity: 'medium'
  tag gid: 'V-75941'
  tag rid: 'SV-90629r1_rule'
  tag stig_id: 'CACT-AG-000009'
  tag gtitle: 'SRG-NET-000147-ALG-000095'
  tag fix_id: 'F-82579r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
