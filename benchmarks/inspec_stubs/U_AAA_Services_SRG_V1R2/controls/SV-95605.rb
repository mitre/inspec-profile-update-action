control 'SV-95605' do
  title 'AAA Services must be configured to require multifactor authentication using Common Access Card (CAC) Personal Identity Verification (PIV) credentials for authenticating non-privileged user accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system. 

Multifactor authentication uses two or more factors to achieve authentication. 

Factors include:
(i) Something you know (e.g., password/PIN); 
(ii) Something you have (e.g., cryptographic identification device, token); or 
(iii) Something you are (e.g., biometric). 

A non-privileged account is any information system account with authorizations of a non-privileged user. 

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

Applications integrating with the DoD Active Directory and using the DoD CAC are examples of compliant multifactor authentication solutions.'
  desc 'check', 'Verify AAA Services are configured to require multifactor authentication using CAC PIV credentials for authenticating non-privileged user accounts.

If AAA Services are not configured to require multifactor authentication using CAC PIV credentials for authenticating non-privileged user accounts, this is a finding.'
  desc 'fix', 'Configure AAA Services to require multifactor authentication using CAC PIV credentials for authenticating non-privileged user accounts.'
  impact 0.5
  ref 'DPMS Target SRG-APP-AAA'
  tag check_id: 'C-80633r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80895'
  tag rid: 'SV-95605r1_rule'
  tag stig_id: 'SRG-APP-000150-AAA-000410'
  tag gtitle: 'SRG-APP-000150-AAA-000410'
  tag fix_id: 'F-87751r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
