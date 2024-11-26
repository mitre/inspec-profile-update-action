control 'SV-222527' do
  title 'The application must use multifactor (Alt. Token) authentication for local access to privileged accounts.'
  desc "Multifactor authentication requires using two or more factors to achieve authentication and access.

Factors include:
(i) something a user knows (e.g., password/PIN);
(ii) something a user has (e.g., cryptographic identification device, token); or
(iii) something a user is (e.g., biometric).

Multifactor authentication decreases the attack surface by virtue of the fact that attackers must obtain two factors, a physical token or a biometric and a PIN, in order to authenticate.  It is not enough to simply steal a user's password to obtain access.  

A privileged account is defined as an information system account with authorizations of a privileged user.  

An Alt. Token is a separate CAC or token used specifically for administrative account access and serves as a separate identifier much like a separate user account.

Local access is defined as access to an organizational information system by a user (or process acting on behalf of a user) communicating through a direct connection without the use of a network."
  desc 'check', 'Review the application documentation and interview the application administrator to identify application access methods.

Ask the application administrator to present both their primary CAC and their Alt. Token.  Ask the application administrator to log on to the application using the local application console.  

Attempt to use both the CAC and Alt. Tokens to authenticate to the application. 

Validate the application requests the user to input their CAC PIN and that they cannot perform administrative functions.

Have user logoff and reauthenticate with their Alt. Token and that they can perform administrative functions.

If the application allows administrative access to the application without requiring an Alt. Token, this is a finding.'
  desc 'fix', 'Configure the application to only use Alt. Tokens when locally accessing privileged application accounts.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24197r493489_chk'
  tag severity: 'medium'
  tag gid: 'V-222527'
  tag rid: 'SV-222527r879592_rule'
  tag stig_id: 'APSC-DV-001590'
  tag gtitle: 'SRG-APP-000151'
  tag fix_id: 'F-24186r493490_fix'
  tag 'documentable'
  tag legacy: ['SV-84159', 'V-69537']
  tag cci: ['CCI-000767']
  tag nist: ['IA-2 (3)']
end
