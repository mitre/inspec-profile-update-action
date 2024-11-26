control 'SV-223596' do
  title 'IBM z/OS DFMSM resource class(es)must be defined to the GSO SAFDEF record in accordance with security requirements.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., web servers and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include: identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include: access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.'
  desc 'check', 'From the ISPF Command Shell enter:
ACF
SET CONTROL(GSO)
SHOW SAFDEF

If both FACILITY and PROGRAM resource classes are defined, this is not a finding.'
  desc 'fix', 'Define the GSO SAFDEF record with the following definitions:

FACILITY
PROGRAM

Ensure both resource classes above are defined.

Example:
SHOW SAFDEF

SET C(GSO)
INSERT SAFDEF.FAC FUNCRET(4) FUNCRSN(0) ID(FACILITY) MODE(GLOBAL) RACROUTE(REQUEST=AUTH CLASS=FACILITY) RETCODE(4)

F ACF2,REFRESH(ALL)'
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25269r504758_chk'
  tag severity: 'medium'
  tag gid: 'V-223596'
  tag rid: 'SV-223596r533198_rule'
  tag stig_id: 'ACF2-SM-000040'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25257r504759_fix'
  tag 'documentable'
  tag legacy: ['SV-107001', 'V-97897']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
