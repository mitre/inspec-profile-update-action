control 'SV-215738' do
  title 'The BIG-IP Core implementation must be configured to enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.'
  desc 'Successful authentication must not automatically give an entity access to an asset or security boundary. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DoD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.

Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. 

ALGs must use these policies and mechanisms to control access on behalf of the application for which it is acting as intermediary and access control mechanisms are required.'
  desc 'check', 'If the BIG-IP Core does not provide user access control intermediary services for virtual servers, this is not applicable.

When user access control intermediary services are provided, verify the BIG-IP Core is configured as follows:

Verify Virtual Server(s) in the BIG-IP LTM module are configured with an APM policy to enforce approved authorizations for logical access to information and system resources employing identity-based, role-based, and/or attribute-based security policies.

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Access Policy" section, that "Access Policy" has been set to use an access policy to enforce approved authorizations for logical access to information.

If the BIG-IP Core is not configured to enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the BIG-IP Core as follows: 

Configure a policy in the BIG-IP APM module to enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.

Apply the APM policy to the applicable Virtual Server(s) in the BIG-IP LTM module to enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16930r291027_chk'
  tag severity: 'medium'
  tag gid: 'V-215738'
  tag rid: 'SV-215738r557356_rule'
  tag stig_id: 'F5BI-LT-000003'
  tag gtitle: 'SRG-NET-000015-ALG-000016'
  tag fix_id: 'F-16928r291028_fix'
  tag 'documentable'
  tag legacy: ['SV-74687', 'V-60257']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
