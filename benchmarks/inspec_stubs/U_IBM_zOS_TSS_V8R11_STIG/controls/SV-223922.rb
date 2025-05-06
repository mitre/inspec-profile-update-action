control 'SV-223922' do
  title 'CA-TSS AUTH Control Option values specified must be set to (OVERRIDE,ALLOVER) or (MERGE,ALLOVER).'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'TSS MODIFY STATUS

If the AUTH Control Option values are not set to AUTH(OVERRIDE, ALLOVER) or AUTH(MERGE, ALLOVER), this is a finding.'
  desc 'fix', 'Configure the AUTH control option is set to (OVERRIDE, ALLOVER) or (MERGE, ALLOVER). With (OVERRIDE, ALLOVER), TSS separately searches first the user, then profiles, and then the ALL record for its access authorization. With (MERGE, ALLOVER), TSS merges and searches the user and all profiles, and then the ALL record for its access authorization. Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option setting to AUTH(OVERRIDE, ALLOVER) or AUTH(MERGE, ALLOVER) and proceed with the change.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25595r516165_chk'
  tag severity: 'medium'
  tag gid: 'V-223922'
  tag rid: 'SV-223922r877763_rule'
  tag stig_id: 'TSS0-ES-000490'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25583r516166_fix'
  tag 'documentable'
  tag legacy: ['V-98551', 'SV-107655']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
