control 'SV-223423' do
  title 'The number of ACF2 users granted the special privilege PPGM must be justified.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
SET LID 
SET VERBOSE 
LIST IF(PPGM)

If the number of users granted the special privilege PPGM is strictly controlled and limited to systems programmer and operations personnel, this is not a finding.'
  desc 'fix', 'Ensure that access to the special privilege PPGM is kept to a minimum and limited to systems programmer and operations personnel.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25096r500399_chk'
  tag severity: 'medium'
  tag gid: 'V-223423'
  tag rid: 'SV-223423r533198_rule'
  tag stig_id: 'ACF2-ES-000020'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25084r500400_fix'
  tag 'documentable'
  tag legacy: ['V-97543', 'SV-106647']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
