control 'SV-68621' do
  title 'The ALG must enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.'
  desc 'Successful authentication must not automatically give an entity access to an asset or security boundary. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DoD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.

Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. ALGs must use these policies and mechanisms to control access on behalf of the application for which it is acting as intermediary.'
  desc 'check', 'Verify the ALG is configured to enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.

If the ALG is not configured to enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies, this is a finding.'
  desc 'fix', 'Configure the ALG to enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-54991r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54375'
  tag rid: 'SV-68621r1_rule'
  tag stig_id: 'SRG-NET-000015-ALG-000016'
  tag gtitle: 'SRG-NET-000015-ALG-000016'
  tag fix_id: 'F-59229r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
