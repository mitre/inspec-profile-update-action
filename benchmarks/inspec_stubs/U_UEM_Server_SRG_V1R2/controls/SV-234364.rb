control 'SV-234364' do
  title 'The UEM server must implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

A non-privileged account is any operating system account with authorizations of a non-privileged user. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators. 

'
  desc 'check', 'Requirement is Not Applicable when UEM server is configured to use DoD Central Directory Service for administrator account authentication.

Verify the UEM server implements replay-resistant authentication mechanisms for network access to non-privileged accounts.

If the UEM server does not implement replay-resistant authentication mechanisms for network access to non-privileged accounts, this is a finding.'
  desc 'fix', 'Configure the UEM server to implement replay-resistant authentication mechanisms for network access to non-privileged accounts.'
  impact 0.5
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37549r614102_chk'
  tag severity: 'medium'
  tag gid: 'V-234364'
  tag rid: 'SV-234364r879598_rule'
  tag stig_id: 'SRG-APP-000157-UEM-000091'
  tag gtitle: 'SRG-APP-000157'
  tag fix_id: 'F-37514r614103_fix'
  tag satisfies: ['FIA \nReference:PP-MDM-414003']
  tag 'documentable'
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
