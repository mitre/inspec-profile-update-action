control 'SV-85985' do
  title 'The CA API Gateway providing user authentication intermediary services must uniquely identify and authenticate non-organizational users (or processes acting on behalf of non-organizational users).'
  desc 'Lack of authentication enables anyone to gain access to the network or possibly a network element that provides opportunity for intruders to compromise resources within the network infrastructure. By identifying and authenticating non-organizational users, their access to network resources can be restricted accordingly.

Non-organizational users will be uniquely identified and authenticated for all accesses other than those accesses explicitly identified and documented by the organization when related to the use of anonymous access. Authorization requires an individual account identifier that has been approved, assigned, and configured on an authentication server. Authentication of user identities is accomplished through the use of passwords, tokens, biometrics, or in the case of multifactor authentication, some combination thereof.

This control applies to application layer gateways that provide content filtering and proxy services on network segments (e.g., DMZ) that allow access by non-organizational users. This requirement focuses on authentication requests to the proxied application for access to destination resources and policy filtering decisions, rather than administrator and management functions.

The CA API Gateway must provide for the use of an internal identity provider that can be used in conjunction with organizational directories such as Active Directory. The internal identity provider can be used for those users not explicitly defined within the organization or for users that exist outside of the organization.'
  desc 'check', %q(Open the CA API GW - Policy manager and click the "Identity Providers" tab.

Verify a provider is listed and designated as the Identity Provider for non-organizational users in accordance with organizational requirements. Verify that non-organizational users are present within this provider. 

Open the CA API GW - Policy Manager and double-click the Registered Services requiring Certificate mapping to User Accounts. 

Verify that the "Require SSL/TLS with Client Certificate Authentication" Assertion is present, that "Extract Attributes from Certificate" is present, and that one of the "Authenticate Against..." Assertions is also present. In addition, verify that the logic necessary to provide access to the Registered Service's resources is properly enabled using the required Policy Logic after extracting the proper attributes from the certificate using the "Extract Attributes from Certificate" Assertion. 

If these requirements have not been met within the policy, this is a finding.)
  desc 'fix', %q(Open the CA API GW - Policy manager and click the "Identity Providers" tab. Right-click "Identity Providers" and create the provider/s utilized for non-organizational users in accordance with organizational requirements. Add non-organizational users to the provider as necessary. 

Open the CA API GW - Policy Manager and double-click the Registered Services requiring Certificate mapping to User Accounts. Update the policy with the "Require SSL/TLS with Client Certificate Authentication", the "Extract Attributes from Certificate", and one of the "Authenticate Against..." Assertions. 

In addition, create the Policy Logic necessary to provide access to the Registered Service's resources after extracting the proper attributes from the certificate using the "Extract Attributes from Certificate" Assertion in accordance with organizational requirements.)
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71761r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71361'
  tag rid: 'SV-85985r1_rule'
  tag stig_id: 'CAGW-GW-000360'
  tag gtitle: 'SRG-NET-000169-ALG-000102'
  tag fix_id: 'F-77671r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000804']
  tag nist: ['IA-8']
end
