control 'SV-79469' do
  title 'The DataPower Gateway must enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.'
  desc 'Successful authentication must not automatically give an entity access to an asset or security boundary. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DoD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.

Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. ALGs must use these policies and mechanisms to control access on behalf of the application for which it is acting as intermediary.'
  desc 'check', 'Privileged account user log on to default domain >> Administration >> Access >> User Group >> Select the group to be confirmed >> Confirm that the access profiles are configured appropriately for the desired security policy.

If the group profile(s) is/are not present, this is a finding

Privileged account user log on to default domain >> Administration >> Access >> RBM Settings >> Select "Credential Mapping".

If Credential-mapping method is not "Local user group" or "Search LDAP for group name" is off, this is a finding.'
  desc 'fix', 'Create the appropriate User Group(s) using the "RBM Builder". Privileged account user log on to default domain >> Administration >> Access >> User Group >> Select the "Add" button >> Define the policy, per the RBM Builder documentation >> Click "Add" >> Click “Apply”.

Add users’ accounts to LDAP groups with the same names as those defined with the RBM Builder, in the remote Authentication/Authorization server (LDAP). 

Note: This takes place outside of the context of the IBM DataPower Gateway. Specific instructions will depend on the LDAP server being used.

Configure Role-Based Management to use LDAP Group information during logon to map users to local group definitions.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 ALG'
  tag check_id: 'C-65637r2_chk'
  tag severity: 'medium'
  tag gid: 'V-64979'
  tag rid: 'SV-79469r1_rule'
  tag stig_id: 'WSDP-AG-000001'
  tag gtitle: 'SRG-NET-000015-ALG-000016'
  tag fix_id: 'F-70919r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
