control 'SV-223426' do
  title 'The number of ACF2 users granted the special privilege ALLCMDS must be justified.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET LID 
SET VERBOSE 
LIST IF(ALLCMDS) 

If the number of users granted the special privilege ALLCMDS is strictly controlled and access is granted on an as needed basis, this is not a finding.

If the number of users granted the special privilege ALLCMDS is not strictly controlled and access is granted on an as needed basis, this is a finding.'
  desc 'fix', 'Ensure that access to the special privilege ALLCMDS is kept to a minimum and is controlled and documented.

Documentation providing justification for access is maintained and filed with the ISSO. 

Remove any unjustified access.'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25099r500408_chk'
  tag severity: 'medium'
  tag gid: 'V-223426'
  tag rid: 'SV-223426r533198_rule'
  tag stig_id: 'ACF2-ES-000050'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25087r500409_fix'
  tag 'documentable'
  tag legacy: ['V-97549', 'SV-106653']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
