control 'SV-223923' do
  title 'Access to the CA-TSS MODE resource class must be appropriate.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOHAS MODE(*)

If any ACIDs is permitted a mode of "DORM", "WARN", or "IMPL", this is a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the removal of this access. Develop a plan of action to ensure that the ACIDs use the default MODE settings and proceed with the change.'
  impact 0.7
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25596r516168_chk'
  tag severity: 'high'
  tag gid: 'V-223923'
  tag rid: 'SV-223923r877764_rule'
  tag stig_id: 'TSS0-ES-000500'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25584r516169_fix'
  tag 'documentable'
  tag legacy: ['V-98553', 'SV-107657']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
