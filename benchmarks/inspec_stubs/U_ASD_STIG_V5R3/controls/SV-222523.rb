control 'SV-222523' do
  title 'The application must use multifactor (Alt. Token) authentication for network access to privileged accounts.'
  desc "Multifactor authentication requires using two or more factors to achieve authentication and access.

Factors include:
(i) something a user knows (e.g., password/PIN);
(ii) something a user has (e.g., cryptographic identification device, token); or
(iii) something a user is (e.g., biometric).

Multifactor authentication decreases the attack surface by virtue of the fact that attackers must obtain two factors, a physical token or a biometric and a PIN, in order to authenticate.  It is not enough to simply steal a user's password to obtain access.  

A privileged account is defined as an information system account with authorizations of a privileged user.  

An Alt. Token is a separate CAC like token used specifically for administrative account access and serves as a separate identifier much like a separate user account.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the Internet)."
  desc 'check', 'Review the application documentation and interview the application administrator to identify application access methods.

Ask the application administrator to present both their primary CAC and their Alt. Token.  Ask the application administrator to log on to the application using application relevant network based access methods.  Attempt to use both CAC and Alt. Tokens to authenticate to the application. 

Validate the application requests the user to input their CAC PIN and that they cannot perform administrative functions.

Have user logoff and reauthenticate with their Alt. Token and that they can perform administrative functions.

If the application allows administrative access to the application without requiring an Alt. Token, this is a finding.'
  desc 'fix', 'Configure the application to use an Alt. Token when providing network access to privileged application accounts.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24193r493477_chk'
  tag severity: 'medium'
  tag gid: 'V-222523'
  tag rid: 'SV-222523r879590_rule'
  tag stig_id: 'APSC-DV-001550'
  tag gtitle: 'SRG-APP-000149'
  tag fix_id: 'F-24182r493478_fix'
  tag 'documentable'
  tag legacy: ['V-69529', 'SV-84151']
  tag cci: ['CCI-000765']
  tag nist: ['IA-2 (1)']
end
