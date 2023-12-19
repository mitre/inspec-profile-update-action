control 'SV-85979' do
  title 'The ALG providing user authentication intermediary services must use multifactor authentication for network access to non-privileged accounts.'
  desc 'To assure accountability and prevent unauthenticated access, non-privileged users must utilize multifactor authentication to prevent potential misuse and compromise of the system.

Multifactor authentication uses two or more factors to achieve authentication. Factors include: 

1) Something you know (e.g., password/PIN), 
2) Something you have (e.g., cryptographic, identification device, token), and 
3) Something you are (e.g., biometric).

Non-privileged accounts are not authorized access to the network element regardless of access method.

Network access is any access to an application by a user (or process acting on behalf of a user) where said access is obtained through a network connection.

Authenticating with a PKI credential and entering the associated PIN is an example of multifactor authentication.

The CA API Gateway supports X.509, username/password, SAML, Kerberos, and RADIUS authentication. To provide multifactor authentication, the CA API Gateway must include a policy that uses multiple authentication assertions and include a route assertion that routes to a biometric back-end service and then evaluate the response to allow/disallow access to the Registered Service.'
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Double-click the Registered Services requiring multifactor authentication. 

For example, within the policy that leverages an RSA SecurID hardware token along with X.509, verify the policy includes a "Require SSL/TLS with Client Certificate" Assertion, which will validate the certificate according to organizational requirements, then use that certificate to authenticate against LDAP or Active Directory using the "Authenticate Against Identity Provider" Assertion, and then include the value from the hardware token in a request to the RSA SecurID RADIUS service via the" Authenticate Against RADIUS Server" Assertion. 

If the policy is not configured with multiple factors for authentication in a similar fashion, this is a finding. 

Additionally, to meet the biometric requirement, check for the existence of an "HTTP(S) Route" assertion, which routes to a back-end biometric validation web service. If the biometric route assertion is not present, this is also a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

Double-click the Registered Services requiring multifactor authentication that were not properly configured. 

For example, within the policy that leverages an RSA SecurID hardware token along with X.509, verify/add the "Require SSL/TLS with Client Certificate" Assertion, which will validate the certificate according to organizational requirements, then using that certificate to authenticate against LDAP or Active Directory, verify/add the "Authenticate Against Identity Provider" Assertion, and then verify/include the value from the hardware token in a request to the RSA SecurID RADIUS service via the "Authenticate Against RADIUS Server" Assertion.

Additionally, to meet the biometric requirement, verify/add an "HTTP(S) Route" Assertion configured to route to a back-end biometric validation web service.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71755r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71355'
  tag rid: 'SV-85979r1_rule'
  tag stig_id: 'CAGW-GW-000330'
  tag gtitle: 'SRG-NET-000140-ALG-000094'
  tag fix_id: 'F-77665r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000766']
  tag nist: ['IA-2 (2)']
end
