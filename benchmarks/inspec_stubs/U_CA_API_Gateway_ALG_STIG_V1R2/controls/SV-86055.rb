control 'SV-86055' do
  title 'The CA API Gateway providing user authentication intermediary services must implement multifactor authentication for remote access to non-privileged accounts such that one of the factors is provided by a device separate from the system gaining access.'
  desc 'For remote access to non-privileged accounts, the purpose of requiring a device that is separate from the information system gaining access for one of the factors during multifactor authentication is to reduce the likelihood of compromising authentication credentials stored on the system.

Multifactor solutions that require devices separate from information systems gaining access include, for example, hardware tokens providing time-based or challenge-response authenticators and smart cards such as the U.S. Government Personal Identity Verification card and the DoD Common Access Card.

A privileged account is defined as an information system account with authorizations of a privileged user.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

An example of compliance with this requirement is the use of a one-time password token and PIN coupled with a password or the use of a CAC/PIV card and PIN coupled with a password.

The CA API Gateway supports X.509, username/password, SAML, Kerberos, and RADIUS authentication. To provide multifactor authentication (MFA), the registered services requiring MFA must include multiple authentication assertions.'
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Double-click the Registered Services requiring multifactor authentication. 

For example, within the policy that leverages an RSA SecurID hardware token along with X.509, verify the policy includes a "Require SSL/TLS with Client Certificate" Assertion, which will validate the certificate according to organizational requirements, then use that certificate to authenticate against LDAP or Active Directory using the "Authenticate Against Identity Provider" Assertion, and then include the value from the hardware token in a request to the RSA SecurID RADIUS service via the "Authenticate Against RADIUS Server" Assertion. 

If the policy is not configured with multiple factors for authentication in a similar fashion, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

Double-click the Registered Services requiring multifactor authentication. 

For example, within the policy, configure the policy to leverage an RSA SecurID hardware token along with X.509 by adding a "Require SSL/TLS with Client Certificate" Assertion, which will validate the certificate according to organizational requirements, then using that certificate to authenticate against LDAP or Active Directory, add an "Authenticate Against Identity Provider" Assertion, and then include the value from the hardware token in a request to the RSA SecurID RADIUS service by adding the "Authenticate Against RADIUS Server" Assertion.

Configure additional Registered Services in a similar fashion in accordance with organizational requirements.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71821r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71431'
  tag rid: 'SV-86055r1_rule'
  tag stig_id: 'CAGW-GW-000610'
  tag gtitle: 'SRG-NET-000339-ALG-000090'
  tag fix_id: 'F-77749r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001951']
  tag nist: ['IA-2 (11)']
end
