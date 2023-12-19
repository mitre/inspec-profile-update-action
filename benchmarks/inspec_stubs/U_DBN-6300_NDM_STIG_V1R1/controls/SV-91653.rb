control 'SV-91653' do
  title 'The DBN-6300 must implement replay-resistant authentication mechanisms for network access to privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Verify SSL is configured to use SSL for the web management tool.

Navigate to Settings >> Initial Configuration >> Security.

If the check box for "Enforce secure communications (SSL) for user interface access" is not checked, this is a finding.'
  desc 'fix', 'Enable SSL for use with the web management tool.

Navigate to Settings >> Initial Configuration >> Security.

Select the check box for "Enforce secure communications (SSL) for user interface access".

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76583r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76957'
  tag rid: 'SV-91653r1_rule'
  tag stig_id: 'DBNW-DM-000053'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-83653r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
