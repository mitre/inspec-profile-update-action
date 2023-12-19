control 'SV-223924' do
  title 'Data set masking characters must be properly defined to the CA-TSS security database.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
TSS WHOOWNS data set(*)

If data set masking characters. (*, %, and +, **) are owned by the MSCA, this is not a finding.'
  desc 'fix', 'Configure all data set masking characters to be owned the MSCA.

Example TSS commands to protect masking characters:

TSS ADD(msca) DSN(*)
TSS ADD(msca) DSN(%)
TSS ADD(msca) DSN(+)'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25597r516171_chk'
  tag severity: 'medium'
  tag gid: 'V-223924'
  tag rid: 'SV-223924r561402_rule'
  tag stig_id: 'TSS0-ES-000505'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25585r516172_fix'
  tag 'documentable'
  tag legacy: ['V-98555', 'SV-107659']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
