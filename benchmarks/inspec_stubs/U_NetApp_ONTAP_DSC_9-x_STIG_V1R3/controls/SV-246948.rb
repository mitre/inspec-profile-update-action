control 'SV-246948' do
  title 'ONTAP must implement replay-resistant authentication mechanisms for network access to privileges accounts.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack.

An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. 

Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.'
  desc 'check', 'Use "security login show -role admin" to see all configured admin users and groups. 

If any account, other than the admin account used as the account of last resort, has an authentication method other than domain, this is a finding.'
  desc 'fix', 'Configure new administrator active directory users or groups with "security login create -user-or-group-name <user_name> -role admin -authentication-method domain".'
  impact 0.5
  ref 'DPMS Target NetApp ONTAP DSC 9.x'
  tag check_id: 'C-50380r860686_chk'
  tag severity: 'medium'
  tag gid: 'V-246948'
  tag rid: 'SV-246948r860687_rule'
  tag stig_id: 'NAOT-IA-000002'
  tag gtitle: 'SRG-APP-000156-NDM-000250'
  tag fix_id: 'F-50334r769175_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
