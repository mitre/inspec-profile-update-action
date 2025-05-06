control 'SV-204747' do
  title 'The application server must use multifactor authentication for local access to privileged accounts.'
  desc 'Multifactor authentication creates a layered defense and makes it more difficult for an unauthorized person to access the application server.  If one factor is compromised or broken, the attacker still has at least one more barrier to breach before successfully breaking into the target.  Unlike a simple username/password scenario where the attacker could gain access by knowing both the username and password without the user knowing his account was compromised, multifactor authentication adds the requirement that the attacker must have something from the user, such as a token, or to biometrically be the user.

Multifactor authentication is defined as: using two or more factors to achieve authentication. 

Factors include: 
(i) something a user knows (e.g., password/PIN); 
(ii) something a user has (e.g., cryptographic identification device, token); or 
(iii) something a user is (e.g., biometric). A CAC or PKI Hardware Token meets this definition.

A privileged account is defined as an information system account with authorizations of a privileged user.  These accounts would be capable of accessing the command line management interface.

When accessing the application server via a local connection, administrative access to the application server must be PKI hardware token enabled.'
  desc 'check', 'Review the application server configuration to ensure the system is authenticating via multifactor authentication for privileged users.

If all aspects of application server command line management interfaces are not authenticating privileged users via multifactor authentication methods, this is a finding.'
  desc 'fix', 'Configure the application server to authenticate privileged users via multifactor authentication for local access to the management interface.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4867r282888_chk'
  tag severity: 'medium'
  tag gid: 'V-204747'
  tag rid: 'SV-204747r508029_rule'
  tag stig_id: 'SRG-APP-000151-AS-000103'
  tag gtitle: 'SRG-APP-000151'
  tag fix_id: 'F-4867r282889_fix'
  tag 'documentable'
  tag legacy: ['V-35301', 'SV-46588']
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
