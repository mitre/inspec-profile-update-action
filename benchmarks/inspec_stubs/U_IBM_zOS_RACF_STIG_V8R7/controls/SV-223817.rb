control 'SV-223817' do
  title 'IBM z/OS DFSMS-related RACF classes must be active.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From an ISPF Command Shell enter:
SETRopts list

If ACTIVE CLASSES lists the MGMTCLAS, STORCLAS, PROGRAM, and FACILITY resources classes, this is not a finding.'
  desc 'fix', 'Configure SETRopts to include MGMTCLAS, STORCLAS, PROGRAM, and FACILITY resources classes as ACTIVE.

The classes can be activated with the command:
SETR CLASSACT(MGMTCLAS STORCLAS PROGRAM FACILITY)

The classes can be RACLISTED with the command:
SETR RACL(MGMTCLAS STORCLAS)'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25490r515139_chk'
  tag severity: 'medium'
  tag gid: 'V-223817'
  tag rid: 'SV-223817r604139_rule'
  tag stig_id: 'RACF-SM-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25478r515140_fix'
  tag 'documentable'
  tag legacy: ['V-98341', 'SV-107445']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
