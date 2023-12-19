control 'SV-223926' do
  title 'CA-TSS ACIDs must not have access to FAC(*ALL*).'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS LIST(ACIDS) DATA(BASIC)

If any ACID(s) is (are) assigned FACILITY(*ALL*), this is a finding.'
  desc 'fix', 'The ISSO will ensure that blanket access to all facilities; FACILITY(ALL), is never granted.

Review all access to FACILITY(*ALL*). Evaluate the impact of correcting the deficiency. Develop a plan of action and remove access to FAC(*ALL*).

Example:
TSS REM(acid) FAC(ALL)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25599r516177_chk'
  tag severity: 'medium'
  tag gid: 'V-223926'
  tag rid: 'SV-223926r561402_rule'
  tag stig_id: 'TSS0-ES-000520'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25587r516178_fix'
  tag 'documentable'
  tag legacy: ['SV-107663', 'V-98559']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
