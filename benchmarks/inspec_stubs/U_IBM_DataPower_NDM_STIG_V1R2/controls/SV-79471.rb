control 'SV-79471' do
  title 'The DataPower Gateway must enforce the assigned privilege level for each administrator and authorizations for access to all commands relative to the privilege level in accordance with applicable policy for the device.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Network devices use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the network device to control access between administrators (or processes acting on behalf of administrators) and objects (e.g., device commands, files, records, processes) in the network device.'
  desc 'check', 'Administration >> Access >> User Group >> Click the group to be confirmed >> Confirm that the access profiles are configured appropriately for the desired security policy. If the group profile(s) is/are not present, this is a finding

Privileged account user log on to default domain >> Administration >> Access >> RBM Settings >> Click "Credential Mapping" >> If Credential-mapping method is not "Local user group" or "Search LDAP for group name" is off, this is a finding.'
  desc 'fix', %q(Create the appropriate User Group(s) using the "RBM Builder": Privileged account user log on to default domain >> Administration >> Access >> User Group >> Click the "Add" button >> Define the policy >> Click "Add" >> Click “Apply”.

Add users' accounts to LDAP groups with the same names as those defined with the RBM Builder, in the remote Authentication/Authorization server (LDAP). Note: This takes place outside the context of the IBM DataPower Gateway. Specific instructions will depend on the LDAP server being used.

Configure Role-Based Management to make use of LDAP Group information during logon to map users to local group definitions.)
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65639r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64981'
  tag rid: 'SV-79471r1_rule'
  tag stig_id: 'WSDP-NM-000013'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag fix_id: 'F-70921r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
