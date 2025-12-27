control 'SV-104181' do
  title 'Symantec ProxySG must implement security policies that enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.'
  desc 'Successful authentication must not automatically give an entity access to an asset or security boundary. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DoD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.

Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. ALGs must use these policies and mechanisms to control access on behalf of the application for which it is acting as intermediary.'
  desc 'check', %q(Obtain the SSP with the site's security policy. Verify that identity-based, role-based, and/or attribute-based authorization is configured for access to proxied websites. Verify that security policies and rules are configured and applied.

1. Log on to the Web Management Console. 
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". 
4. For each rule within each Web Access Layer, verify that the "Source" column for each rule contains something other than "any" (any is the default value). Verify that rules comply with the site's security policy.

If Symantec ProxySG does not implement security policies that enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies, this is a finding.)
  desc 'fix', %q(Obtain the SSP with the site's security policy. Configure the ProxySG to enforce approved authorizations by employing identity-based, role-based, and/or attribute-based authorization for access to proxied websites.

1. Log on to the web Management Console.
2. Click Configuration >> Visual Policy Manager. 
3. Click "Launch". 
4. For each Web Access Layer that is configured, right-click the "Source" of each column and click "Set".
5. Select the users, groups, roles, and attributes as required by the site's security policy.
6. Click File >> Install Policy on SG Appliance.)
  impact 0.7
  ref 'DPMS Target Symantec ProxySG ALG'
  tag check_id: 'C-93413r1_chk'
  tag severity: 'high'
  tag gid: 'V-94227'
  tag rid: 'SV-104181r1_rule'
  tag stig_id: 'SYMP-AG-000060'
  tag gtitle: 'SRG-NET-000015-ALG-000016'
  tag fix_id: 'F-100343r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
