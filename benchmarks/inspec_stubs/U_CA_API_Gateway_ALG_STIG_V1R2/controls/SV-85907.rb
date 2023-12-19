control 'SV-85907' do
  title 'The CA API Gateway must enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.'
  desc 'Successful authentication must not automatically give an entity access to an asset or security boundary. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DoD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.

Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

The CA API Gateway has the ability to integrate with third-party identity providers such as Active Directory. Users within the identity providers should be granted access to the Registered Services as needed through the use of policies within the Registered Services.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. ALGs must use these policies and mechanisms to control access on behalf of the application for which it is acting as intermediary.'
  desc 'check', 'Open the CA API Gateway - Policy Manager. 

Double-click all Registered Services and verify the "Request: Authenticate User or Group" assertion has been added and enabled within the Services in accordance with organizational requirements. 

If it has not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager. 

Double-click all Registered Services and add the "Authenticate User or Group" assertion. 

Select from a list of Identity providers in the drop-down list and click "Search". 

Chose from the list of users and groups to grant/authorize access to the Registered Service and click "Select".'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71673r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71283'
  tag rid: 'SV-85907r1_rule'
  tag stig_id: 'CAGW-GW-000100'
  tag gtitle: 'SRG-NET-000015-ALG-000016'
  tag fix_id: 'F-77589r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
