control 'SV-215714' do
  title 'The BIG-IP APM module must enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.'
  desc 'Successful authentication must not automatically give an entity access to an asset or security boundary. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DoD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.

Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. ALGs must use these policies and mechanisms to control access on behalf of the application for which it is acting as intermediary.'
  desc 'check', 'If the BIG-IP APM module does not provide user access control intermediary services  as part of the traffic management functions of the BIG-IP Core, this is not applicable.

Verify the BIG-IP APM module is configured to enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.

Navigate to the BIG-IP System manager >> Access Policy >> Access Profiles >> Access Profiles List.

Review Access Policy Profiles to verify configuration for authorization by employing identity-based, role-based, and/or attribute-based security policies.

If the BIG-IP APM is not configured to enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided  as part of the traffic management functions of the BIG-IP Core, configure the BIG-IP APM module to enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Access Policy Manager 11.x'
  tag check_id: 'C-16907r290388_chk'
  tag severity: 'medium'
  tag gid: 'V-215714'
  tag rid: 'SV-215714r557355_rule'
  tag stig_id: 'F5BI-AP-000003'
  tag gtitle: 'SRG-NET-000015-ALG-000016'
  tag fix_id: 'F-16905r290389_fix'
  tag 'documentable'
  tag legacy: ['V-59929', 'SV-74359']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
