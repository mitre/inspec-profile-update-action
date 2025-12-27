control 'SV-96011' do
  title 'The Central Log Server must be configured to enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 

This requirement is applicable to access control enforcement applications (e.g., authentication servers) and other applications that perform information and system access control functions.'
  desc 'check', 'Verify the Central Log Server user accounts are configured for granular permissions to separate and control access levels of accounts used to access the application. Users should not have access permissions that are not relevant to their role.

If the Central Log Server is not configured to enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies, this is a finding.'
  desc 'fix', 'Configure the Central Log Server with granular permissions to separate and control access levels of accounts used to access the application.'
  impact 0.7
  ref 'DPMS Target SRG-APP-LOG'
  tag check_id: 'C-80999r1_chk'
  tag severity: 'high'
  tag gid: 'V-81297'
  tag rid: 'SV-96011r1_rule'
  tag stig_id: 'SRG-APP-000033-AU-001610'
  tag gtitle: 'SRG-APP-000033-AU-001610'
  tag fix_id: 'F-88081r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
